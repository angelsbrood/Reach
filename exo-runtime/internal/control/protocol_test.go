package control

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

type bufferStream struct{ bytes.Buffer }

func TestCodecRoundTrip(t *testing.T) {
	stream := &bufferStream{}
	codec := NewCodec(stream)
	want := Message{Type: "ping", Epoch: strings.Repeat("a", 32), Sequence: 9}
	if err := codec.Send(want); err != nil {
		t.Fatal(err)
	}
	got, err := codec.Receive(time.Now(), func(time.Time) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestCodecRefusesOversizedAndUnknown(t *testing.T) {
	stream := &bufferStream{}
	codec := NewCodec(stream)
	if err := codec.Send(Message{Type: "failed", Reason: strings.Repeat("x", MaxMessageBytes)}); err == nil {
		t.Fatal("oversized send succeeded")
	}
	stream.WriteString(`{"type":"ping","unknown":true}` + "\n")
	if _, err := NewCodec(stream).Receive(time.Now(), func(time.Time) error { return nil }); err == nil {
		t.Fatal("unknown control field succeeded")
	}
}

func TestMessageBoundsAndTypes(t *testing.T) {
	if err := (Message{Type: "pong"}).ValidateInbound("pong"); err != nil {
		t.Fatal(err)
	}
	if err := (Message{Type: "start"}).ValidateInbound("pong"); err == nil {
		t.Fatal("wrong type succeeded")
	}
	if err := (Message{Type: "failed", Reason: strings.Repeat("x", 257)}).ValidateInbound("failed"); err == nil {
		t.Fatal("oversized reason succeeded")
	}
}
