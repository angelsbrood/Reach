package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"reach.dev/exo-runtime/internal/bootstrap"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout io.Writer) error {
	if err := validatePlatform(runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	if len(arguments) == 0 {
		return errors.New("usage: reach-exo-bootstrap (create|verify|recover) [options]")
	}
	switch arguments[0] {
	case "create":
		flags := privateFlagSet("create")
		inventoryPath := flags.String("inventory", "", "absolute path to the strict inventory JSON")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *inventoryPath == "" {
			return errors.New("create requires exactly --inventory /absolute/path/inventory.json")
		}
		inventory, _, digest, err := bootstrap.LoadInventory(*inventoryPath, time.Now().UTC())
		if err != nil {
			return err
		}
		_, err = bootstrap.Create(inventory, digest, stdout)
		return err
	case "verify":
		flags := privateFlagSet("verify")
		root := flags.String("authority-root", "", "absolute prepared authority root")
		expected := flags.String("expected-authority-sha256", "", "external lowercase SHA-256 commitment")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *root == "" || *expected == "" {
			return errors.New("verify requires --authority-root and --expected-authority-sha256")
		}
		verification, err := bootstrap.Verify(*root, *expected)
		if err != nil {
			return err
		}
		output, err := bootstrap.MarshalVerification(verification)
		if err != nil {
			return err
		}
		return writeDirect(stdout, output)
	case "recover":
		flags := privateFlagSet("recover")
		discard := flags.Bool("discard-uncommitted", false, "discard one attributable uncommitted state")
		confirm := flags.Bool("confirm-discard-uncommitted", false, "confirm destructive discard")
		inventoryPath := flags.String("inventory", "", "absolute path to the same strict inventory JSON")
		target := flags.String("target", "", "staging, prepared, or quarantine")
		state := flags.String("commitment-state", "", "absent or partial")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || !*discard || !*confirm || *inventoryPath == "" || *target == "" || *state == "" {
			return errors.New("recover requires --discard-uncommitted, --confirm-discard-uncommitted, --inventory, --target, and --commitment-state")
		}
		inventory, _, digest, err := bootstrap.LoadInventoryForRecovery(*inventoryPath)
		if err != nil {
			return err
		}
		if err := bootstrap.Recover(inventory, digest, bootstrap.RecoveryTarget(*target), bootstrap.CommitmentState(*state), true); err != nil {
			return err
		}
		return writeDirect(stdout, []byte("{\"schema_version\":1,\"discarded_uncommitted\":true}\n"))
	default:
		return fmt.Errorf("unknown bootstrap command %q", arguments[0])
	}
}

func validatePlatform(goos, goarch string) error {
	if goarch != "arm64" || (goos != "darwin" && goos != "linux") {
		return errors.New("reach-exo-bootstrap requires Darwin/arm64 or Linux/arm64")
	}
	return nil
}

func privateFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	return flags
}

func writeDirect(writer io.Writer, data []byte) error {
	written := 0
	for written < len(data) {
		count, err := writer.Write(data[written:])
		if count < 0 || count > len(data)-written {
			return errors.New("stdout writer returned invalid count")
		}
		written += count
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
