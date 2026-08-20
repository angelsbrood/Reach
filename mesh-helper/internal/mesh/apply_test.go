// SPDX-License-Identifier: MIT

package mesh

import (
	"errors"
	"strings"
	"testing"
)

func TestApplyResponseDistinguishesRefusalFromUnknownTransportOutcome(t *testing.T) {
	expected := authorityIdentity{generation: 9, digest: strings.Repeat("a", 64)}
	if err := applyResponse(expected, renderApplyResponse("ok", expected), nil); err != nil {
		t.Fatal(err)
	}
	refused := applyResponse(expected, "error\n", nil)
	if refused == nil || !strings.Contains(refused.Error(), "refused generation 9") {
		t.Fatalf("explicit refusal = %v", refused)
	}
	staged := applyResponse(expected, renderApplyResponse("staged", expected), nil)
	if staged == nil || !strings.Contains(staged.Error(), "generation 9 remains staged") || strings.Contains(staged.Error(), "accepted") {
		t.Fatalf("staged outcome = %v", staged)
	}
	if message, ok := PublicApplyOutcome(staged); !ok || message != staged.Error() {
		t.Fatalf("public staged outcome = %q ok=%t", message, ok)
	}
	unknown := applyResponse(expected, "", errors.New("connection closed"))
	if unknown == nil || !strings.Contains(unknown.Error(), "did not report its final outcome") ||
		strings.Contains(unknown.Error(), "refused") {
		t.Fatalf("unknown outcome = %v", unknown)
	}
	if _, ok := PublicApplyOutcome(errors.New("private backend detail")); ok {
		t.Fatal("an internal error was exposed as a public apply outcome")
	}
}

func TestApplyResponseRequiresExactRequestedAuthority(t *testing.T) {
	expected := authorityIdentity{generation: 13, digest: strings.Repeat("b", 64)}
	wrongGeneration := authorityIdentity{generation: 12, digest: expected.digest}
	if err := applyResponse(expected, renderApplyResponse("ok", wrongGeneration), nil); err == nil ||
		!strings.Contains(err.Error(), "different authority at generation 12 than requested generation 13") {
		t.Fatalf("wrong generation response = %v", err)
	}
	wrongDigest := authorityIdentity{generation: expected.generation, digest: strings.Repeat("c", 64)}
	if err := applyResponse(expected, renderApplyResponse("ok", wrongDigest), nil); err == nil ||
		!strings.Contains(err.Error(), "different authority at generation 13 than requested generation 13") {
		t.Fatalf("wrong digest response = %v", err)
	}
	if err := applyResponse(expected, "ok\n", nil); err == nil || !strings.Contains(err.Error(), "invalid outcome") {
		t.Fatalf("unbound legacy response = %v", err)
	}
}

func TestApplyControlProtocolIsStrictAndRoundTripsAuthority(t *testing.T) {
	expected := authorityIdentity{generation: 13, digest: strings.Repeat("d", 64)}
	parsed, err := parseApplyRequest(renderApplyRequest(expected))
	if err != nil || parsed != expected {
		t.Fatalf("request round trip = %+v err=%v", parsed, err)
	}
	outcome, applied, err := parseApplyResponseLine(renderApplyResponse("ok", expected))
	if err != nil || outcome != "ok" || applied != expected {
		t.Fatalf("response round trip = outcome=%q authority=%+v err=%v", outcome, applied, err)
	}
	for _, invalid := range []string{
		"apply\n",
		"apply 0 " + expected.digest + "\n",
		"apply 13 " + strings.ToUpper(expected.digest) + "\n",
		"apply 13 " + expected.digest + " extra\n",
		" apply 13 " + expected.digest + "\n",
		"apply 13 " + expected.digest,
	} {
		if _, err := parseApplyRequest(invalid); err == nil {
			t.Fatalf("invalid request accepted: %q", invalid)
		}
	}
}
