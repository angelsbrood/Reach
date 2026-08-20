// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"os"

	"systems.reach/mesh-helper/internal/mesh"
)

func main() {
	if err := run(os.Args); err != nil {
		message := "operation failed"
		if outcome, ok := mesh.PublicApplyOutcome(err); ok {
			message = outcome
		}
		fmt.Fprintf(os.Stderr, "reach-meshd: %s\n", message)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 2 && arguments[1] == "serve" {
		return mesh.ServeSystem()
	}
	if len(arguments) == 2 && arguments[1] == "version" {
		fmt.Println(mesh.HelperVersion)
		return nil
	}
	if len(arguments) == 4 && arguments[1] == "apply" && arguments[2] == "--input" && arguments[3] != "" {
		return mesh.ApplyFromSudo(mesh.SystemPaths(), arguments[3])
	}
	return errors.New("usage: reach-meshd serve | reach-meshd apply --input PATH | reach-meshd version")
}
