package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"reach.dev/exo-runtime/internal/authority"
)

func TestDocumentAlwaysCarriesExactPackageGeneration(t *testing.T) {
	root := t.TempDir()
	writer := &Writer{Root: root}
	if err := writer.Write(Document{Role: "worker", State: "waiting"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document Document
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.PackageVersion != authority.BundleVersion || document.PackageGeneration != authority.PackageGeneration {
		t.Fatalf("status package authority differs: %#v", document)
	}
}
