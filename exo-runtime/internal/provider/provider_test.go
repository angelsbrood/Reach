package provider

import (
	"slices"
	"strings"
	"testing"

	"reach.dev/exo-runtime/internal/authority"
)

func TestCommandLineUsesFrozenConsoleEntrypoint(t *testing.T) {
	epoch := "0123456789abcdef0123456789abcdef"
	program, arguments := commandLine(epoch, "worker", "reach-exo-s47")
	if program != authority.ProgramRoot+"/provider/.venv/bin/exo" {
		t.Fatalf("program %q is not the frozen console entrypoint", program)
	}
	if slices.Contains(arguments, "-m") || !slices.Contains(arguments, "--offline") || !slices.Contains(arguments, "--no-downloads") {
		t.Fatalf("worker arguments do not preserve the frozen offline boundary: %q", arguments)
	}
	if slices.Contains(arguments, "--no-api") || slices.Contains(arguments, "--force-master") {
		t.Fatalf("worker must retain its peer-confined topology probe API without claiming master: %q", arguments)
	}
	_, coordinator := commandLine(epoch, "coordinator", "reach-exo-s47")
	if !slices.Contains(coordinator, "--force-master") || slices.Contains(coordinator, "--no-api") {
		t.Fatalf("coordinator arguments do not preserve the exact master/API role: %q", coordinator)
	}
}

func TestProviderEnvironmentDoesNotInstallProxy(t *testing.T) {
	values := providerEnvironment("0123456789abcdef0123456789abcdef")
	if !slices.Contains(values, "TMPDIR="+authority.StateRoot+"/tmp") || slices.Contains(values, "TMPDIR="+authority.RuntimeRoot+"/tmp") {
		t.Fatal("provider TMPDIR must use the removable executable state root, not noexec /run")
	}
	for _, value := range values {
		name, _, _ := strings.Cut(value, "=")
		if strings.HasSuffix(strings.ToUpper(name), "_PROXY") {
			t.Fatalf("provider environment contains proxy key %q", name)
		}
	}
}
