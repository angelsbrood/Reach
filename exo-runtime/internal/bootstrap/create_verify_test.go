package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type deterministicReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func newDeterministicReader(seed string) *deterministicReader {
	return &deterministicReader{seed: []byte(seed)}
}

func (r *deterministicReader) Read(destination []byte) (int, error) {
	written := 0
	for written < len(destination) {
		if len(r.buffer) == 0 {
			var counter [8]byte
			binary.BigEndian.PutUint64(counter[:], r.counter)
			r.counter++
			digest := sha256.Sum256(append(append([]byte{}, r.seed...), counter[:]...))
			r.buffer = append([]byte{}, digest[:]...)
		}
		count := copy(destination[written:], r.buffer)
		written += count
		r.buffer = r.buffer[count:]
	}
	return written, nil
}

type createdAuthority struct {
	inventory       Inventory
	inventoryDigest string
	result          CreateResult
	output          []byte
	verification    Verification
}

func createAuthority(t *testing.T, seed string) createdAuthority {
	t.Helper()
	root := testRoot(t)
	inventory := validInventory(root)
	data, _ := json.Marshal(inventory)
	_, _, digest, err := DecodeInventory(data, testNow)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	result, err := createWithDependencies(inventory, digest, &output, dependencies{now: func() time.Time { return testNow }, rand: newDeterministicReader(seed), hook: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), result.Commitment) || result.AcceptedBytes != len(result.Commitment) || !strings.Contains(string(output.Bytes()), result.AuthoritySHA256) {
		t.Fatal("commitment output does not exactly match create result")
	}
	verification, err := verifyAt(root, result.AuthoritySHA256, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return createdAuthority{inventory: inventory, inventoryDigest: digest, result: result, output: append([]byte{}, output.Bytes()...), verification: verification}
}

func TestCreateAndIndependentVerify(t *testing.T) {
	created := createAuthority(t, "create-and-verify")
	if !created.verification.Valid || created.verification.AuthoritySHA256 != created.result.AuthoritySHA256 || created.verification.PackageGeneration != exactAuthority().PackageGeneration {
		t.Fatal("verification result differs from exact authority")
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(created.inventory.AuthorityRoot), "."+filepath.Base(created.inventory.AuthorityRoot)+stagingSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("staging path survived successful publication")
	}
}

func TestIdenticalInventoryHasStableTopologyAndFreshCredentials(t *testing.T) {
	root := testRoot(t)
	inventory, digest := testInventoryAndDigest(t, root)
	var firstOutput bytes.Buffer
	firstResult, err := createWithDependencies(inventory, digest, &firstOutput, testDependencies("first-credentials"))
	if err != nil {
		t.Fatal(err)
	}
	first := createdAuthority{inventory: inventory, inventoryDigest: digest, result: firstResult}
	firstManifest, err := readStrictJSON[ClusterManifest](filepath.Join(first.inventory.AuthorityRoot, clusterManifestName), maxManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, quarantine := deterministicPaths(root)
	if err := quarantineAndRemove(root, quarantine, testDependencies("between-ceremonies")); err != nil {
		t.Fatal(err)
	}
	var secondOutput bytes.Buffer
	secondResult, err := createWithDependencies(inventory, digest, &secondOutput, testDependencies("second-credentials"))
	if err != nil {
		t.Fatal(err)
	}
	second := createdAuthority{inventory: inventory, inventoryDigest: digest, result: secondResult}
	secondManifest, err := readStrictJSON[ClusterManifest](filepath.Join(second.inventory.AuthorityRoot, clusterManifestName), maxManifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstManifest.Topology, secondManifest.Topology) {
		t.Fatal("public semantic topology changed across ceremonies")
	}
	if firstManifest.Certificates == secondManifest.Certificates || firstManifest.BootstrapAuthorityID == secondManifest.BootstrapAuthorityID {
		t.Fatal("independent ceremonies reused credentials or authority identifier")
	}
}

type boundedWriter struct {
	buffer    bytes.Buffer
	chunk     int
	failAfter int
	fullError bool
	zero      bool
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	if w.failAfter >= 0 && w.buffer.Len() >= w.failAfter {
		return 0, errors.New("injected writer failure")
	}
	limit := len(data)
	if w.chunk > 0 && limit > w.chunk {
		limit = w.chunk
	}
	if w.failAfter >= 0 && w.buffer.Len()+limit > w.failAfter {
		limit = w.failAfter - w.buffer.Len()
	}
	count, _ := w.buffer.Write(data[:limit])
	if w.fullError && count == len(data) {
		return count, errors.New("simultaneous final-byte error")
	}
	if w.failAfter >= 0 && w.buffer.Len() >= w.failAfter {
		return count, errors.New("injected writer failure")
	}
	return count, nil
}

func TestCommitmentShortWritesAndFailureSettlement(t *testing.T) {
	for name, writer := range map[string]*boundedWriter{
		"one byte writes":   {chunk: 1, failAfter: -1},
		"seven byte writes": {chunk: 7, failAfter: -1},
	} {
		t.Run(name, func(t *testing.T) {
			root := testRoot(t)
			inventory, digest := testInventoryAndDigest(t, root)
			result, err := createWithDependencies(inventory, digest, writer, testDependencies(name))
			if err != nil || writer.buffer.Len() != len(result.Commitment) {
				t.Fatalf("short writer did not converge: %v", err)
			}
			if _, err := verifyAt(root, result.AuthoritySHA256, testNow); err != nil {
				t.Fatal(err)
			}
		})
	}

	for name, writer := range map[string]*boundedWriter{
		"zero progress": {zero: true, failAfter: -1},
		"first byte":    {chunk: 1, failAfter: 1},
		"middle":        {chunk: 5, failAfter: 35},
	} {
		t.Run(name, func(t *testing.T) {
			root := testRoot(t)
			inventory, digest := testInventoryAndDigest(t, root)
			_, err := createWithDependencies(inventory, digest, writer, testDependencies(name))
			if err == nil || errors.Is(err, ErrCommitmentCompleteOrUncertain) {
				t.Fatalf("partial commitment was not a normal failed delivery: %v", err)
			}
			assertNoAttributablePaths(t, root)
		})
	}
}

func TestEveryCommitmentByteBoundaryIsClassified(t *testing.T) {
	record := []byte(fmt.Sprintf(commitmentRecordFormat, strings.Repeat("0", 64)))
	for boundary := 0; boundary < len(record); boundary++ {
		t.Run(fmt.Sprintf("partial-%03d", boundary), func(t *testing.T) {
			writer := &boundedWriter{chunk: 1, failAfter: boundary}
			accepted, err := writeCommitment(writer, record, testDependencies("byte-boundary"))
			if err == nil || accepted != boundary || writer.buffer.Len() != boundary {
				t.Fatalf("boundary classification differs: accepted=%d output=%d err=%v", accepted, writer.buffer.Len(), err)
			}
		})
	}
	writer := &boundedWriter{chunk: 1, failAfter: -1}
	accepted, err := writeCommitment(writer, record, testDependencies("complete-boundary"))
	if err != nil || accepted != len(record) || !bytes.Equal(writer.buffer.Bytes(), record) {
		t.Fatalf("complete boundary differs: accepted=%d err=%v", accepted, err)
	}
}

func TestCompleteCommitmentWithErrorPreservesPreparedTree(t *testing.T) {
	root := testRoot(t)
	inventory, digest := testInventoryAndDigest(t, root)
	writer := &boundedWriter{failAfter: -1, fullError: true}
	result, err := createWithDependencies(inventory, digest, writer, testDependencies("complete-error"))
	if !errors.Is(err, ErrCommitmentCompleteOrUncertain) || result.AcceptedBytes != len(result.Commitment) {
		t.Fatalf("complete-or-uncertain state differs: %v", err)
	}
	if _, statErr := os.Stat(root); statErr != nil {
		t.Fatal("prepared tree was deleted after a complete commitment")
	}
	if _, err := verifyAt(root, result.AuthoritySHA256, testNow); err != nil {
		t.Fatal(err)
	}
}

func TestWrongMissingAndMalformedExternalCommitmentsRefuse(t *testing.T) {
	created := createAuthority(t, "expected-digest")
	for name, expected := range map[string]string{
		"missing": "", "uppercase": strings.ToUpper(created.result.AuthoritySHA256),
		"short": created.result.AuthoritySHA256[:62], "wrong": strings.Repeat("0", 64),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyAt(created.inventory.AuthorityRoot, expected, testNow); err == nil {
				t.Fatal("invalid external commitment was accepted")
			}
		})
	}
}

func TestCreateRefusesNoncanonicalInventoryDigestBeforePublication(t *testing.T) {
	root := testRoot(t)
	inventory, _ := testInventoryAndDigest(t, root)
	if _, err := createWithDependencies(inventory, strings.Repeat("0", 64), &bytes.Buffer{}, testDependencies("wrong-inventory-digest")); err == nil {
		t.Fatal("noncanonical inventory digest was accepted")
	}
	assertNoAttributablePaths(t, root)
}

func TestWholeAuthoritySubstitutionRefusesOriginalCommitment(t *testing.T) {
	first := createAuthority(t, "substitution-one")
	second := createAuthority(t, "substitution-two")
	if _, err := verifyAt(second.inventory.AuthorityRoot, first.result.AuthoritySHA256, testNow); err == nil {
		t.Fatal("different internally valid authority matched the original commitment")
	}
}

func TestExpiredAndNotYetValidCertificatesRefuse(t *testing.T) {
	created := createAuthority(t, "validity")
	if _, err := verifyAt(created.inventory.AuthorityRoot, created.result.AuthoritySHA256, testNow.Add(31*24*time.Hour)); err == nil {
		t.Fatal("expired authority was accepted")
	}
	if _, err := verifyAt(created.inventory.AuthorityRoot, created.result.AuthoritySHA256, testNow.Add(-6*time.Minute)); err == nil {
		t.Fatal("not-yet-valid authority was accepted")
	}
}

func testInventoryAndDigest(t *testing.T, root string) (Inventory, string) {
	t.Helper()
	inventory := validInventory(root)
	data, _ := json.Marshal(inventory)
	_, _, digest, err := DecodeInventory(data, testNow)
	if err != nil {
		t.Fatal(err)
	}
	return inventory, digest
}

func testRoot(t *testing.T) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "authority")
}

func testDependencies(seed string) dependencies {
	return dependencies{now: func() time.Time { return testNow }, rand: newDeterministicReader(seed), hook: func(string) error { return nil }}
}

func assertNoAttributablePaths(t *testing.T, root string) {
	t.Helper()
	staging, quarantine := deterministicPaths(root)
	for _, path := range []string{root, staging, quarantine} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("attributable path survived: %s (%v)", path, err)
		}
	}
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var _ io.Writer = (*boundedWriter)(nil)
