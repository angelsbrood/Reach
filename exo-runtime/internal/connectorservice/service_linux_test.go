//go:build linux

package connectorservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reach.dev/exo-runtime/internal/config"
)

func fixture(t *testing.T) (string, config.Connector) {
	t.Helper()
	root := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "reach-exo-connector"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	files := config.TLSFiles{CA: filepath.Join(root, "ca.pem"), Certificate: filepath.Join(root, "client.pem"), PrivateKey: filepath.Join(root, "key.pem")}
	for _, f := range []struct {
		p, kind string
		b       []byte
		mode    os.FileMode
	}{{files.CA, "CERTIFICATE", caDER, 0644}, {files.Certificate, "CERTIFICATE", certDER, 0644}, {files.PrivateKey, "PRIVATE KEY", private, 0600}} {
		if err = os.WriteFile(f.p, pem.EncodeToMemory(&pem.Block{Type: f.kind, Bytes: f.b}), f.mode); err != nil {
			t.Fatal(err)
		}
	}
	value := config.Connector{SchemaVersion: 1, ListenAddress: "127.0.0.1:52415", GatewayAddress: "192.168.118.3:53421", ServerName: "reach-exo-gateway", TLS: files}
	path := filepath.Join(root, "connector.json")
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, value
}

func TestReadyMeansServingLocalRoutesWithoutUpstream(t *testing.T) {
	path, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := 0
	err := Run(ctx, path, func(message string) error {
		if strings.HasPrefix(message, "READY=1") {
			ready++
			client := &http.Client{Timeout: time.Second}
			response, err := client.Get("http://127.0.0.1:52415/state")
			if err != nil {
				return err
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusNotFound {
				t.Errorf("route status=%d", response.StatusCode)
			}
			cancel()
		}
		return nil
	})
	if err != nil || ready != 1 {
		t.Fatalf("ready=%d err=%v", ready, err)
	}
	assertClosed(t, "127.0.0.1:52415")
}

func TestStartupFailuresNeverNotifyReady(t *testing.T) {
	for _, stage := range []string{"configuration", "credentials", "tls", "listener", "notification"} {
		t.Run(stage, func(t *testing.T) {
			path, value := fixture(t)
			var occupied net.Listener
			var err error
			switch stage {
			case "configuration":
				if err = os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "credentials":
				if err = os.Chmod(value.TLS.PrivateKey, 0644); err != nil {
					t.Fatal(err)
				}
			case "tls":
				if err = os.WriteFile(value.TLS.Certificate, []byte("invalid certificate"), 0644); err != nil {
					t.Fatal(err)
				}
			case "listener":
				occupied, err = net.Listen("tcp4", value.ListenAddress)
				if err != nil {
					t.Fatal(err)
				}
				defer occupied.Close()
			}
			attempts := 0
			err = Run(context.Background(), path, func(string) error { attempts++; return io.ErrClosedPipe })
			var startup *StartupError
			if !errors.As(err, &startup) {
				t.Fatalf("not startup failure: %v", err)
			}
			if stage != "notification" && attempts != 0 {
				t.Fatal("invalid startup attempted readiness")
			}
			if stage == "notification" && (attempts != 1 || startup.Stage != "notification") {
				t.Fatal("failed notification accepted")
			}
			if stage != "listener" {
				assertClosed(t, value.ListenAddress)
			}
		})
	}
}

func TestShutdownBoundsActiveHTTPAndCancelsRequest(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	ready := make(chan struct{})
	active := make(chan struct{})
	handlerDone := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(active)
		<-r.Context().Done()
		close(handlerDone)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, listener, server, func(s string) error {
			if strings.HasPrefix(s, "READY=1") {
				close(ready)
			}
			return nil
		})
	}()
	<-ready
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	<-active
	started := time.Now()
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown unbounded")
	}
	if elapsed := time.Since(started); elapsed < 2800*time.Millisecond || elapsed > 4500*time.Millisecond {
		t.Fatalf("shutdown duration %s", elapsed)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("active request not cancelled")
	}
	assertClosed(t, address)
}

func TestUnexpectedServeFailureIsRuntimeFailure(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serve(context.Background(), listener, &http.Server{}, func(string) error { close(ready); return nil })
	}()
	<-ready
	_ = listener.Close()
	select {
	case err = <-done:
		var startup *StartupError
		if err == nil || errors.As(err, &startup) {
			t.Fatalf("runtime classification %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve failure did not settle")
	}
}

func assertClosed(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", address, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("listener survived service return")
	}
}
