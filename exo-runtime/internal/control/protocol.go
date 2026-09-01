// Package control defines the bounded coordinator-to-worker control protocol.
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const MaxMessageBytes = 16 * 1024

type Message struct {
	Type              string `json:"type"`
	Epoch             string `json:"epoch,omitempty"`
	ClosureHash       string `json:"closure_hash,omitempty"`
	PackageVersion    string `json:"package_version,omitempty"`
	PackageGeneration string `json:"package_generation,omitempty"`
	BootID            string `json:"boot_id,omitempty"`
	ProviderPID       int    `json:"provider_pid,omitempty"`
	Reason            string `json:"reason,omitempty"`
	Sequence          uint64 `json:"sequence,omitempty"`
}

func (m Message) ValidateInbound(allowed ...string) error {
	found := false
	for _, value := range allowed {
		found = found || m.Type == value
	}
	if !found {
		return fmt.Errorf("control type %q is not allowed", m.Type)
	}
	if len(m.Epoch) > 96 || len(m.ClosureHash) > 128 || len(m.PackageVersion) > 32 || len(m.PackageGeneration) > 192 || len(m.BootID) > 128 || len(m.Reason) > 256 {
		return errors.New("control field exceeds bound")
	}
	return nil
}

type Codec struct {
	reader *bufio.Reader
	writer io.Writer
}

func NewCodec(stream io.ReadWriter) *Codec {
	return &Codec{reader: bufio.NewReaderSize(stream, MaxMessageBytes), writer: stream}
}

func (c *Codec) Send(m Message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(data)+1 > MaxMessageBytes {
		return errors.New("control message exceeds bound")
	}
	data = append(data, '\n')
	_, err = c.writer.Write(data)
	return err
}

func (c *Codec) Receive(deadline time.Time, setDeadline func(time.Time) error) (Message, error) {
	if err := setDeadline(deadline); err != nil {
		return Message{}, err
	}
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return Message{}, err
	}
	if len(line) > MaxMessageBytes {
		return Message{}, errors.New("control message exceeds bound")
	}
	var message Message
	decoder := json.NewDecoder(bufio.NewReaderSize(bytesReader(line), len(line)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return Message{}, fmt.Errorf("decode control message: %w", err)
	}
	return message, nil
}

type byteReader struct {
	value []byte
}

func bytesReader(value []byte) *byteReader { return &byteReader{value: value} }

func (r *byteReader) Read(target []byte) (int, error) {
	if len(r.value) == 0 {
		return 0, io.EOF
	}
	n := copy(target, r.value)
	r.value = r.value[n:]
	return n, nil
}
