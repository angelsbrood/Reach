package lifecycle

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"reach.dev/exo-runtime/internal/config"
	"reach.dev/exo-runtime/internal/control"
)

func TestEpochBarrierRequiresSettlement(t *testing.T) {
	var barrier EpochBarrier
	if err := barrier.Begin("one"); err != nil {
		t.Fatal(err)
	}
	if err := barrier.Begin("two"); err == nil {
		t.Fatal("unsettled epoch was crossed")
	}
	if err := barrier.Settle("other"); err == nil {
		t.Fatal("wrong epoch settled")
	}
	if err := barrier.Settle("one"); err != nil {
		t.Fatal(err)
	}
	if err := barrier.Begin("two"); err != nil {
		t.Fatal(err)
	}
}

func TestEpochIdentity(t *testing.T) {
	first, err := newEpoch()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !validEpoch(first) || !validEpoch(second) {
		t.Fatal("fresh epochs are invalid or duplicated")
	}
	for _, bad := range []string{"", "ABC", "0000000000000000000000000000000g", "000000000000000000000000000000000"} {
		if validEpoch(bad) {
			t.Fatalf("invalid epoch %q accepted", bad)
		}
	}
}

func TestProviderEpochRestartBound(t *testing.T) {
	node := NewNode(config.Node{})
	for index := 0; index < maxProviderEpochs; index++ {
		if err := node.claimEpoch(); err != nil {
			t.Fatal(err)
		}
	}
	if err := node.claimEpoch(); err == nil {
		t.Fatal("provider epoch bound was exceeded")
	}
	if node.epochTotal() != maxProviderEpochs {
		t.Fatalf("epoch total %d, want %d", node.epochTotal(), maxProviderEpochs)
	}
}

func TestPeerRecoveryDeadlineStartsAtFailure(t *testing.T) {
	failure := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	if got, want := newPeerRecoveryDeadline(failure), failure.Add(epochReadyBudget); !got.Equal(want) {
		t.Fatalf("deadline %s, want %s", got, want)
	}
	longHealthyEpoch := failure.Add(12 * time.Hour)
	if !newPeerRecoveryDeadline(longHealthyEpoch).After(newPeerRecoveryDeadline(failure)) {
		t.Fatal("healthy epoch did not reset the subsequent recovery window")
	}
}

func TestCoordinatorCancellationIsClean(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := coordinatorTerminalError(canceled); err != nil {
		t.Fatalf("operator cancellation must settle cleanly: %v", err)
	}
	deadline, deadlineCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer deadlineCancel()
	if !errors.Is(coordinatorTerminalError(deadline), context.DeadlineExceeded) {
		t.Fatal("deadline failure was hidden as a clean operator stop")
	}
}

func TestWorkerControlSerializesStopAndSettlement(t *testing.T) {
	coordinator, worker := net.Pipe()
	defer coordinator.Close()
	defer worker.Close()
	epoch := "0123456789abcdef0123456789abcdef"
	workerDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(worker)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			workerDone <- err
			return
		}
		var message control.Message
		if err := json.Unmarshal(line, &message); err != nil {
			workerDone <- err
			return
		}
		if message.Type != "stop" || message.Epoch != epoch {
			workerDone <- &controlSequenceError{message: message}
			return
		}
		response, _ := json.Marshal(control.Message{Type: "settled", Epoch: epoch})
		response = append(response, '\n')
		_, err = worker.Write(response)
		workerDone <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	controller := startWorkerControl(ctx, coordinator, control.NewCodec(coordinator), epoch)
	if err := controller.Stop(); err != nil {
		t.Fatal(err)
	}
	cancel()
	controller.Wait()
	if err := <-workerDone; err != nil {
		t.Fatal(err)
	}
}

func TestWorkerControlPreservesProviderFailure(t *testing.T) {
	coordinator, worker := net.Pipe()
	defer coordinator.Close()
	defer worker.Close()
	epoch := "0123456789abcdef0123456789abcdef"
	go func() {
		codec := control.NewCodec(worker)
		message, err := codec.Receive(time.Now().Add(2*time.Second), worker.SetReadDeadline)
		if err != nil {
			return
		}
		_ = codec.Send(control.Message{Type: "failed", Epoch: message.Epoch, Reason: "worker provider exited: exit status 1"})
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controller := startWorkerControl(ctx, coordinator, control.NewCodec(coordinator), epoch)
	select {
	case err := <-controller.Failures():
		if err == nil || !strings.Contains(err.Error(), "exit status 1") {
			t.Fatalf("provider failure was not preserved: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("provider failure was not delivered")
	}
	controller.Wait()
}

func TestProviderExitReasonIsBounded(t *testing.T) {
	reason := providerExitReason(&controlSequenceError{message: control.Message{Type: strings.Repeat("x", 512)}})
	if len(reason) > 240 || !strings.HasPrefix(reason, "worker provider exited:") {
		t.Fatalf("unexpected bounded reason: %q", reason)
	}
}

type controlSequenceError struct{ message control.Message }

func (e *controlSequenceError) Error() string {
	return "unexpected control sequence: " + e.message.Type
}
