package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"reach.dev/exo-runtime/internal/authority"
	"reach.dev/exo-runtime/internal/config"
	"reach.dev/exo-runtime/internal/lifecycle"
	"reach.dev/exo-runtime/internal/neighbor"
	"reach.dev/exo-runtime/internal/netguard"
	"reach.dev/exo-runtime/internal/relay"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 1 && arguments[0] == "version" {
		fmt.Printf("reach-exo-lifecycle %s exo %s %s\n", authority.BundleVersion, authority.EXOVersion, authority.EXOCommit)
		return nil
	}
	if len(arguments) != 2 {
		return fmt.Errorf("usage: reach-exo-node (run|relay|validate|netguard-apply|netguard-remove|neighbor-apply|neighbor-remove) /etc/reach-exo/node.json")
	}
	path := filepath.Clean(arguments[1])
	if path != authority.ConfigRoot+"/node.json" {
		return fmt.Errorf("node configuration path must be %s/node.json", authority.ConfigRoot)
	}
	value, err := config.LoadNode(path)
	if err != nil {
		return err
	}
	switch arguments[0] {
	case "validate":
		if err := config.ValidateTLSFileModes(value.TLS, true); err != nil {
			return err
		}
		result, _ := json.Marshal(map[string]any{"valid": true, "role": value.Role, "model": authority.ModelID, "schema_version": authority.SchemaVersion})
		fmt.Println(string(result))
		return nil
	case "netguard-apply":
		return netguard.Apply(value)
	case "netguard-remove":
		return netguard.Remove()
	case "neighbor-apply":
		return neighbor.Apply(value)
	case "neighbor-remove":
		return neighbor.Remove(value)
	case "run":
		return lifecycle.RunWithSignals(lifecycle.NewNode(value))
	case "relay":
		return relay.RunWithSignals(value)
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}
