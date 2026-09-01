// Package lifecycle owns worker/coordinator provider epochs and publication.
package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"reach.dev/exo-runtime/internal/authority"
	"reach.dev/exo-runtime/internal/config"
	"reach.dev/exo-runtime/internal/control"
	"reach.dev/exo-runtime/internal/gateway"
	"reach.dev/exo-runtime/internal/mtls"
	"reach.dev/exo-runtime/internal/packageupdate"
	"reach.dev/exo-runtime/internal/provider"
	"reach.dev/exo-runtime/internal/readiness"
	"reach.dev/exo-runtime/internal/status"
)

const (
	heartbeatInterval = time.Second
	heartbeatTimeout  = 4 * time.Second
	providerStopWait  = 15 * time.Second
	epochReadyBudget  = 20 * time.Minute
	stateLimit        = 16 * 1024 * 1024
	maxProviderEpochs = 3
)

type Node struct {
	Config     config.Node
	Provider   *provider.Manager
	Status     *status.Writer
	Gateway    *gateway.Server
	epochMu    sync.Mutex
	epochCount int
}

func (n *Node) expectedCluster() readiness.ExpectedCluster {
	return readiness.ExpectedCluster{
		CoordinatorName:    n.Config.NodeName,
		WorkerName:         n.Config.PeerName,
		CoordinatorAddress: n.Config.PrivateAddress,
		WorkerAddress:      n.Config.PeerAddress,
		Interface:          n.Config.NetworkInterface,
		CoordinatorRange:   readiness.LayerRange{Start: n.Config.ExpectedRange.Start, End: n.Config.ExpectedRange.End},
		WorkerRange:        readiness.LayerRange{Start: n.Config.ExpectedPeerRange.Start, End: n.Config.ExpectedPeerRange.End},
	}
}

func NewNode(value config.Node) *Node {
	return &Node{Config: value, Provider: &provider.Manager{}, Status: &status.Writer{}, Gateway: &gateway.Server{}}
}

func (n *Node) Run(ctx context.Context) error {
	if err := packageupdate.VerifyServiceRuntimeAuthority(packageupdate.DefaultPaths()); err != nil {
		return fmt.Errorf("package runtime authority: %w", err)
	}
	if err := config.ValidateTLSFileModes(n.Config.TLS, true); err != nil {
		return err
	}
	if err := provider.ValidateInstalledLayout(); err != nil {
		return err
	}
	if err := validateNetworkIdentity(n.Config); err != nil {
		return err
	}
	for _, path := range []string{authority.StateRoot + "/tmp", authority.StateRoot + "/config", authority.StateRoot + "/data", authority.StateRoot + "/cache", authority.StateRoot + "/models"} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}
	if n.Config.Role == "worker" {
		return n.runWorker(ctx)
	}
	return n.runCoordinator(ctx)
}

func validateNetworkIdentity(value config.Node) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	if hostname != value.NodeName {
		return fmt.Errorf("hostname %q does not match configured node_name %q", hostname, value.NodeName)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	local := make(map[string]bool)
	for _, address := range addresses {
		ip, _, parseErr := net.ParseCIDR(address.String())
		if parseErr == nil {
			local[ip.String()] = true
		}
	}
	if !local[value.PrivateAddress] {
		return errors.New("configured private_address is not assigned locally")
	}
	if local[value.PeerAddress] || local[value.ConnectorAddress] {
		return errors.New("peer or connector authority is unexpectedly local")
	}
	return nil
}

func (n *Node) runWorker(ctx context.Context) error {
	tlsConfig, err := mtls.Server(n.Config.TLS, "reach-exo-coordinator")
	if err != nil {
		return err
	}
	address := net.JoinHostPort(n.Config.PrivateAddress, fmt.Sprint(authority.ControlPort))
	listener, err := tls.Listen("tcp4", address, tlsConfig)
	if err != nil {
		return err
	}
	defer listener.Close()
	_ = n.Status.Write(status.Document{Role: "worker", State: "waiting", Reason: "awaiting authenticated coordinator"})
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for ctx.Err() == nil {
		if n.epochTotal() >= maxProviderEpochs {
			return errors.New("worker provider epoch restart bound exhausted")
		}
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if err := n.handleWorkerConnection(ctx, connection); err != nil && ctx.Err() == nil {
			_ = n.Status.Write(status.Document{Role: "worker", State: "degraded", Reason: err.Error()})
		}
	}
	_ = n.Provider.Stop(providerStopWait)
	_ = n.Status.Write(status.Document{Role: "worker", State: "stopped"})
	return nil
}

func (n *Node) handleWorkerConnection(ctx context.Context, connection net.Conn) error {
	defer connection.Close()
	codec := control.NewCodec(connection)
	message, err := codec.Receive(time.Now().Add(heartbeatTimeout), connection.SetReadDeadline)
	if err != nil {
		return err
	}
	if err := message.ValidateInbound("start"); err != nil {
		return err
	}
	if !validEpoch(message.Epoch) || message.ClosureHash != authority.DerivativeSHA256 || !exactPackageIdentity(message.PackageVersion, message.PackageGeneration) {
		_ = codec.Send(control.Message{Type: "refused", Reason: "invalid epoch, closure, or package authority"})
		return errors.New("coordinator supplied invalid epoch, closure, or package authority")
	}
	epoch := message.Epoch
	pid, err := n.Provider.Start(message.Epoch, "worker", n.Config.NamespacePrefix)
	if err != nil {
		_ = codec.Send(control.Message{Type: "failed", Reason: "provider start failed"})
		return err
	}
	if err := n.claimEpoch(); err != nil {
		_ = n.Provider.Stop(providerStopWait)
		_ = codec.Send(control.Message{Type: "refused", Reason: "provider epoch bound exhausted"})
		return err
	}
	bootID := readBootID()
	_ = n.Status.Write(status.Document{Role: "worker", State: "running", Epoch: message.Epoch, ProviderPID: pid})
	if err := codec.Send(control.Message{Type: "started", Epoch: message.Epoch, ClosureHash: authority.DerivativeSHA256, PackageVersion: authority.BundleVersion, PackageGeneration: authority.PackageGeneration, BootID: bootID, ProviderPID: pid}); err != nil {
		_ = n.Provider.Stop(providerStopWait)
		return err
	}
	defer func() {
		_ = n.Provider.Stop(providerStopWait)
	}()
	for ctx.Err() == nil {
		message, err = codec.Receive(time.Now().Add(heartbeatTimeout), connection.SetReadDeadline)
		if err != nil {
			return err
		}
		if err := message.ValidateInbound("ping", "stop"); err != nil || message.Epoch != epoch {
			return errors.New("invalid worker control sequence")
		}
		if message.Type == "stop" {
			if err := n.Provider.Stop(providerStopWait); err != nil {
				_ = codec.Send(control.Message{Type: "failed", Epoch: message.Epoch, Reason: "provider did not settle"})
				return err
			}
			_ = codec.Send(control.Message{Type: "settled", Epoch: message.Epoch, BootID: bootID})
			return nil
		}
		running, runErr := n.Provider.Running()
		if !running || runErr != nil {
			reason := providerExitReason(runErr)
			_ = codec.Send(control.Message{Type: "failed", Epoch: message.Epoch, Reason: reason})
			return errors.New(reason)
		}
		if err := codec.Send(control.Message{Type: "pong", Epoch: message.Epoch, BootID: bootID, ProviderPID: n.Provider.PID(), Sequence: message.Sequence}); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (n *Node) runCoordinator(ctx context.Context) error {
	backoff := time.Second
	peerDeadline := newPeerRecoveryDeadline(time.Now())
	_ = n.Status.Write(status.Document{Role: "coordinator", State: "waiting", Reason: "awaiting exact worker"})
	for ctx.Err() == nil {
		if n.epochTotal() >= maxProviderEpochs {
			return errors.New("coordinator provider epoch restart bound exhausted")
		}
		wasReady, err := n.runEpoch(ctx)
		_ = n.Gateway.Close()
		_ = n.Provider.Stop(providerStopWait)
		if ctx.Err() != nil {
			break
		}
		if wasReady {
			peerDeadline = newPeerRecoveryDeadline(time.Now())
			backoff = time.Second
		}
		if time.Now().After(peerDeadline) {
			return fmt.Errorf("finite peer recovery budget exhausted: %w", err)
		}
		reason := "epoch withdrew"
		if err != nil {
			reason = err.Error()
		}
		_ = n.Status.Write(status.Document{Role: "coordinator", State: "degraded", Reason: reason})
		select {
		case <-ctx.Done():
			break
		case <-time.After(backoff):
		}
		if backoff < 15*time.Second {
			backoff *= 2
		}
	}
	_ = n.Status.Write(status.Document{Role: "coordinator", State: "stopped"})
	return coordinatorTerminalError(ctx)
}

func coordinatorTerminalError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	return ctx.Err()
}

func newPeerRecoveryDeadline(failure time.Time) time.Time {
	return failure.Add(epochReadyBudget)
}

func (n *Node) runEpoch(parent context.Context) (bool, error) {
	epoch, err := newEpoch()
	if err != nil {
		return false, err
	}
	tlsConfig, err := mtls.Client(n.Config.TLS, "reach-exo-worker")
	if err != nil {
		return false, err
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 10 * time.Second}
	peerAddress := net.JoinHostPort(n.Config.PeerAddress, fmt.Sprint(authority.ControlPort))
	connection, err := tls.DialWithDialer(dialer, "tcp4", peerAddress, tlsConfig)
	if err != nil {
		return false, fmt.Errorf("worker unavailable: %w", err)
	}
	defer connection.Close()
	codec := control.NewCodec(connection)
	if err := codec.Send(control.Message{Type: "start", Epoch: epoch, ClosureHash: authority.DerivativeSHA256, PackageVersion: authority.BundleVersion, PackageGeneration: authority.PackageGeneration}); err != nil {
		return false, err
	}
	ack, err := codec.Receive(time.Now().Add(heartbeatTimeout), connection.SetReadDeadline)
	if err != nil {
		return false, err
	}
	if !validStartedAcknowledgement(ack, epoch) {
		return false, errors.New("worker did not authenticate a fresh provider start")
	}
	controlCtx, cancelControl := context.WithCancel(context.Background())
	worker := startWorkerControl(controlCtx, connection, codec, epoch)
	defer func() {
		_ = worker.Stop()
		cancelControl()
		worker.Wait()
	}()
	pid, err := n.Provider.Start(epoch, "coordinator", n.Config.NamespacePrefix)
	if err != nil {
		return false, err
	}
	if err := n.claimEpoch(); err != nil {
		_ = n.Provider.Stop(providerStopWait)
		return false, err
	}
	_ = n.Status.Write(status.Document{Role: "coordinator", State: "starting", Epoch: epoch, ProviderPID: pid})
	readyContext, readyCancel := context.WithTimeout(parent, epochReadyBudget)
	defer readyCancel()
	result, err := n.prepareAndWaitReady(readyContext, worker.Failures())
	if err != nil {
		return false, err
	}
	gatewayTLS, err := mtls.Server(n.Config.TLS, "reach-exo-connector")
	if err != nil {
		return false, err
	}
	handler := gateway.Handler(gateway.LocalTransport(), gateway.LocalTarget(), epoch)
	gatewayAddress := net.JoinHostPort(n.Config.PrivateAddress, fmt.Sprint(authority.GatewayPort))
	if err := n.Gateway.Start(gatewayAddress, gatewayTLS, handler); err != nil {
		return false, err
	}
	ids := []string{result.CoordinatorNodeID, result.WorkerNodeID}
	sort.Strings(ids)
	_ = n.Status.Write(status.Document{Role: "coordinator", State: "ready", Epoch: epoch, ProviderPID: pid, StateSHA256: result.StateSHA256, NodeIDs: ids, RunnerIDs: result.RunnerIDs, InstanceID: result.InstanceID})
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-parent.Done():
			_ = n.Gateway.Close()
			if err := worker.Stop(); err != nil {
				return true, fmt.Errorf("worker settlement failed: %w", err)
			}
			return true, parent.Err()
		case err := <-worker.Failures():
			_ = n.Gateway.Close()
			return true, fmt.Errorf("worker control lost: %w", err)
		case <-ticker.C:
			running, runErr := n.Provider.Running()
			if !running || runErr != nil {
				_ = n.Gateway.Close()
				return true, errors.New("coordinator provider exited")
			}
			stateBytes, stateErr := fetchState(parent)
			if stateErr != nil {
				_ = n.Gateway.Close()
				return true, fmt.Errorf("provider state unavailable: %w", stateErr)
			}
			if _, stateErr = readiness.Live(stateBytes, n.expectedCluster()); stateErr != nil {
				_ = n.Gateway.Close()
				return true, fmt.Errorf("topology drift: %w", stateErr)
			}
		}
	}
}

func (n *Node) prepareAndWaitReady(ctx context.Context, heartbeatFailure <-chan error) (readiness.Result, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	placementCreated := false
	for {
		select {
		case <-ctx.Done():
			return readiness.Result{}, ctx.Err()
		case err := <-heartbeatFailure:
			return readiness.Result{}, err
		case <-ticker.C:
			stateBytes, err := fetchState(ctx)
			if err != nil {
				continue
			}
			if !placementCreated {
				state, decodeErr := readiness.Decode(stateBytes)
				if decodeErr != nil {
					continue
				}
				if _, baselineErr := readiness.Baseline(state, n.expectedCluster()); baselineErr != nil {
					continue
				}
				if err := createExactInstance(ctx); err != nil {
					return readiness.Result{}, err
				}
				placementCreated = true
				continue
			}
			result, readyErr := readiness.Ready(stateBytes, n.expectedCluster(), true)
			if readyErr == nil {
				return result, nil
			}
		}
	}
}

type workerControl struct {
	stop     chan chan error
	done     chan struct{}
	failures chan error
}

func startWorkerControl(ctx context.Context, connection net.Conn, codec *control.Codec, epoch string) *workerControl {
	control := &workerControl{stop: make(chan chan error), done: make(chan struct{}), failures: make(chan error, 1)}
	go control.run(ctx, connection, codec, epoch)
	return control
}

func (c *workerControl) run(ctx context.Context, connection net.Conn, codec *control.Codec, epoch string) {
	defer close(c.done)
	var sequence uint64
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-c.stop:
			result <- sendStop(connection, codec, epoch)
			return
		case <-ticker.C:
			sequence++
			if err := connection.SetWriteDeadline(time.Now().Add(heartbeatTimeout)); err != nil {
				c.fail(err)
				return
			}
			if err := codec.Send(control.Message{Type: "ping", Epoch: epoch, Sequence: sequence}); err != nil {
				c.fail(err)
				return
			}
			message, err := codec.Receive(time.Now().Add(heartbeatTimeout), connection.SetReadDeadline)
			if err != nil {
				c.fail(err)
				return
			}
			if err := message.ValidateInbound("pong", "failed"); err != nil || message.Epoch != epoch {
				c.fail(errors.New("invalid worker heartbeat"))
				return
			}
			if message.Type == "failed" {
				reason := message.Reason
				if reason == "" {
					reason = "worker reported an unspecified failure"
				}
				c.fail(errors.New(reason))
				return
			}
			if message.Sequence != sequence || message.ProviderPID <= 0 || message.BootID == "" {
				c.fail(errors.New("invalid worker heartbeat"))
				return
			}
		}
	}
}

func (c *workerControl) fail(err error) {
	select {
	case c.failures <- err:
	default:
	}
}

func (c *workerControl) Failures() <-chan error { return c.failures }

func (c *workerControl) Stop() error {
	result := make(chan error, 1)
	select {
	case c.stop <- result:
		return <-result
	case <-c.done:
		select {
		case err := <-c.failures:
			return err
		default:
			return errors.New("worker control already terminated")
		}
	}
}

func (c *workerControl) Wait() { <-c.done }

func createExactInstance(ctx context.Context) error {
	values := url.Values{}
	values.Set("model_id", authority.ModelID)
	values.Set("sharding", "Pipeline")
	values.Set("instance_meta", "MlxRing")
	values.Set("min_nodes", "2")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/instance/placement?%s", authority.ProviderAPIPort, values.Encode()), nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: gateway.LocalTransport(), Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	placement, err := boundedBody(response, 4*1024*1024)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("placement returned HTTP %d", response.StatusCode)
	}
	body, err := json.Marshal(map[string]json.RawMessage{"instance": placement})
	if err != nil {
		return err
	}
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/instance", authority.ProviderAPIPort), strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	post.Header.Set("Content-Type", "application/json")
	response, err = client.Do(post)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("instance creation returned HTTP %d", response.StatusCode)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1024*1024))
	return err
}

func fetchState(ctx context.Context) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/state", authority.ProviderAPIPort), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: gateway.LocalTransport(), Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("state returned HTTP %d", response.StatusCode)
	}
	return boundedBody(response, stateLimit)
}

func boundedBody(response *http.Response, limit int64) ([]byte, error) {
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("HTTP body exceeds bound")
	}
	return data, nil
}

func sendStop(connection net.Conn, codec *control.Codec, epoch string) error {
	_ = connection.SetWriteDeadline(time.Now().Add(heartbeatTimeout))
	if err := codec.Send(control.Message{Type: "stop", Epoch: epoch}); err != nil {
		return err
	}
	message, err := codec.Receive(time.Now().Add(providerStopWait+heartbeatTimeout), connection.SetReadDeadline)
	if err != nil {
		return err
	}
	if err := message.ValidateInbound("settled"); err != nil || message.Epoch != epoch {
		return errors.New("worker failed to prove settlement")
	}
	return nil
}

func validEpoch(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func exactPackageIdentity(version, generation string) bool {
	return version == authority.BundleVersion && generation == authority.PackageGeneration
}

func validStartedAcknowledgement(message control.Message, epoch string) bool {
	return message.ValidateInbound("started") == nil && message.Epoch == epoch && message.ClosureHash == authority.DerivativeSHA256 && exactPackageIdentity(message.PackageVersion, message.PackageGeneration) && message.ProviderPID > 0 && message.BootID != ""
}

func providerExitReason(err error) string {
	reason := "worker provider exited"
	if err != nil {
		reason += ": " + err.Error()
	}
	if len(reason) > 240 {
		reason = reason[:240]
	}
	return reason
}

func newEpoch() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func readBootID() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func (n *Node) claimEpoch() error {
	n.epochMu.Lock()
	defer n.epochMu.Unlock()
	if n.epochCount >= maxProviderEpochs {
		return errors.New("provider epoch restart bound exhausted")
	}
	n.epochCount++
	return nil
}

func (n *Node) epochTotal() int {
	n.epochMu.Lock()
	defer n.epochMu.Unlock()
	return n.epochCount
}

func RunWithSignals(node *Node) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return node.Run(ctx)
}

// EpochBarrier serializes test and harness decisions around a provider epoch.
type EpochBarrier struct {
	mu      sync.Mutex
	current string
	settled bool
}

func (b *EpochBarrier) Begin(epoch string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current != "" && !b.settled {
		return errors.New("prior epoch is not settled")
	}
	b.current = epoch
	b.settled = false
	return nil
}

func (b *EpochBarrier) Settle(epoch string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current != epoch || b.settled {
		return errors.New("settlement does not match active epoch")
	}
	b.settled = true
	return nil
}
