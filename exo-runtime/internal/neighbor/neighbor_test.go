package neighbor

import (
	"strings"
	"testing"

	"reach.dev/exo-runtime/internal/config"
)

func TestWantedRecordUsesExactConfiguredIdentity(t *testing.T) {
	value := config.Node{NetworkInterface: "eth0", PeerMAC: "52:55:55:b1:1f:d9"}
	got, err := wantedRecord(value)
	if err != nil {
		t.Fatal(err)
	}
	if got.Interface != "eth0" || got.Address != "fe80::5055:55ff:feb1:1fd9" || got.MAC != value.PeerMAC {
		t.Fatalf("unexpected ownership record: %#v", got)
	}
}

func TestInspectRequiresOneStrictKernelObject(t *testing.T) {
	original := runIP
	t.Cleanup(func() { runIP = original })
	wanted := record{SchemaVersion: 1, Interface: "eth0", Address: "fe80::1", MAC: "52:55:55:00:00:01"}
	runIP = func(arguments ...string) ([]byte, error) {
		if strings.Join(arguments, " ") != "-j -6 neighbor show to fe80::1" {
			t.Fatalf("unexpected ip arguments: %q", arguments)
		}
		return []byte(`[{"dst":"fe80::1","dev":"eth0","lladdr":"52:55:55:00:00:01","state":["PERMANENT"]}]`), nil
	}
	values, err := inspect(wanted)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || !sameNeighbor(values[0], wanted) {
		t.Fatalf("kernel state did not match: %#v", values)
	}
	runIP = func(arguments ...string) ([]byte, error) {
		return []byte(`[{"dst":"fe80::1","dev":"eth0","lladdr":"52:55:55:00:00:02","state":["REACHABLE"]}]`), nil
	}
	values, err = inspect(wanted)
	if err != nil {
		t.Fatal(err)
	}
	if sameNeighbor(values[0], wanted) {
		t.Fatal("drifted kernel state was accepted")
	}
}

func TestClearFailedResolutionDeletesOnlyExactMACLessTuple(t *testing.T) {
	original := runIP
	t.Cleanup(func() { runIP = original })
	wanted := record{SchemaVersion: 1, Interface: "eth0", Address: "fe80::5055:55ff:feb1:1fd9", MAC: "52:55:55:b1:1f:d9"}
	calls := 0
	runIP = func(arguments ...string) ([]byte, error) {
		calls++
		switch calls {
		case 1:
			if strings.Join(arguments, " ") != "-6 neighbor del fe80::5055:55ff:feb1:1fd9 dev eth0" {
				t.Fatalf("unexpected delete arguments: %q", arguments)
			}
			return nil, nil
		case 2:
			if strings.Join(arguments, " ") != "-j -6 neighbor show to fe80::5055:55ff:feb1:1fd9" {
				t.Fatalf("unexpected inspect arguments: %q", arguments)
			}
			return []byte("[]"), nil
		default:
			t.Fatalf("unexpected invocation %d: %q", calls, arguments)
			return nil, nil
		}
	}
	cleared, err := clearFailedResolution([]kernelNeighbor{{
		Destination: wanted.Address,
		Device:      wanted.Interface,
		State:       []string{"FAILED"},
	}}, wanted)
	if err != nil {
		t.Fatal(err)
	}
	if !cleared || calls != 2 {
		t.Fatalf("failed tuple was not cleared exactly once: cleared=%v calls=%d", cleared, calls)
	}
}

func TestClearFailedResolutionRefusesAmbiguousState(t *testing.T) {
	original := runIP
	t.Cleanup(func() { runIP = original })
	runIP = func(arguments ...string) ([]byte, error) {
		t.Fatalf("ambiguous tuple must not mutate kernel state: %q", arguments)
		return nil, nil
	}
	wanted := record{SchemaVersion: 1, Interface: "eth0", Address: "fe80::1", MAC: "52:55:55:00:00:01"}
	for _, value := range []kernelNeighbor{
		{Destination: wanted.Address, Device: wanted.Interface, LinkAddress: wanted.MAC, State: []string{"FAILED"}},
		{Destination: wanted.Address, Device: wanted.Interface, State: []string{"INCOMPLETE"}},
		{Destination: wanted.Address, Device: "eth1", State: []string{"FAILED"}},
	} {
		cleared, err := clearFailedResolution([]kernelNeighbor{value}, wanted)
		if err != nil || cleared {
			t.Fatalf("ambiguous tuple admitted: %#v cleared=%v err=%v", value, cleared, err)
		}
	}
}
