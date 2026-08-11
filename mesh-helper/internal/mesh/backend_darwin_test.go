// SPDX-License-Identifier: MIT

package mesh

import (
	"errors"
	"reflect"
	"testing"
)

type recordedSystemCommand struct {
	path      string
	arguments []string
}

func TestConfigureDarwinInterfaceOwnsConnectedMeshRoute(t *testing.T) {
	var commands []recordedSystemCommand
	run := func(path string, arguments ...string) error {
		commands = append(commands, recordedSystemCommand{path: path, arguments: append([]string(nil), arguments...)})
		return nil
	}

	if err := configureDarwinInterface("utun7", testSpecification(t, 1), run); err != nil {
		t.Fatal(err)
	}
	want := []recordedSystemCommand{
		{path: "/sbin/ifconfig", arguments: []string{"utun7", "inet", HostAddress, "10.86.0.1", "alias"}},
		{path: "/sbin/ifconfig", arguments: []string{"utun7", "mtu", "1280"}},
		{path: "/sbin/ifconfig", arguments: []string{"utun7", "up"}},
		{path: "/sbin/route", arguments: []string{"-q", "-n", "add", "-inet", MeshNetwork, "-interface", "utun7"}},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %#v, want %#v", commands, want)
	}
}

func TestConfigureDarwinInterfacePropagatesRouteFailure(t *testing.T) {
	wantError := errors.New("route unavailable")
	var commands []recordedSystemCommand
	run := func(path string, arguments ...string) error {
		commands = append(commands, recordedSystemCommand{path: path, arguments: append([]string(nil), arguments...)})
		if path == "/sbin/route" {
			return wantError
		}
		return nil
	}

	err := configureDarwinInterface("utun9", testSpecification(t, 1), run)
	if !errors.Is(err, wantError) {
		t.Fatalf("error = %v, want %v", err, wantError)
	}
	if len(commands) != 4 {
		t.Fatalf("command count = %d, want 4", len(commands))
	}
}

func TestRemoveDarwinRouteUsesFixedMeshDestination(t *testing.T) {
	var command recordedSystemCommand
	run := func(path string, arguments ...string) error {
		command = recordedSystemCommand{path: path, arguments: append([]string(nil), arguments...)}
		return nil
	}

	if err := removeDarwinRoute(run); err != nil {
		t.Fatal(err)
	}
	want := recordedSystemCommand{
		path:      "/sbin/route",
		arguments: []string{"-q", "-n", "delete", "-inet", MeshNetwork},
	}
	if !reflect.DeepEqual(command, want) {
		t.Fatalf("command = %#v, want %#v", command, want)
	}
}
