package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reach.dev/identity-bootstrap/internal/bootstrap"
	"runtime"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func validatePlatform(goos, goarch string, uid, euid int) error {
	if goos != "linux" || goarch != "arm64" {
		return errors.New("reach-identity-bootstrap requires Linux/arm64")
	}
	if uid == 0 || euid == 0 || uid != euid {
		return errors.New("an unprivileged operator is required")
	}
	return nil
}

func run(args []string, stdout io.Writer) error {
	if err := validatePlatform(runtime.GOOS, runtime.GOARCH, os.Getuid(), os.Geteuid()); err != nil {
		return err
	}
	if len(args) == 0 || (args[0] != "create" && args[0] != "verify") {
		return errors.New("usage: reach-identity-bootstrap (create|verify) --config /absolute/request.json [options]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "absolute request path")
	var output, bundle, expected *string
	if args[0] == "create" {
		output = f.String("output", "", "new absolute private output directory")
	} else {
		bundle = f.String("bundle", "", "absolute private bundle directory")
		expected = f.String("expected-ca-sha256", "", "external CA DER fingerprint")
	}
	if err := f.Parse(args[1:]); err != nil {
		return errors.New("invalid command options")
	}
	if f.NArg() != 0 || *config == "" || (output != nil && *output == "") || (bundle != nil && (*bundle == "" || *expected == "")) {
		return errors.New("all command options must be supplied explicitly")
	}
	request, err := bootstrap.LoadRequest(*config)
	if err != nil {
		return err
	}
	var result bootstrap.Result
	if output != nil {
		result, err = bootstrap.Create(request, *output)
	} else {
		result, err = bootstrap.Verify(request, *bundle, *expected)
	}
	if err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	for len(data) > 0 {
		n, err := stdout.Write(data)
		if n < 0 || n > len(data) {
			return errors.New("invalid stdout write count")
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
