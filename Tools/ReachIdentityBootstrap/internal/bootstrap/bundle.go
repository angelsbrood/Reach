package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type clientBundle struct {
	ClusterName      string `json:"clusterName"`
	CACertificateDER []byte `json:"caCertificateDER"`
	CertificateDER   []byte `json:"certificateDER"`
	PrivateKeyX963   []byte `json:"privateKeyX963"`
}

type Result struct {
	SchemaVersion int    `json:"schema_version"`
	Valid         bool   `json:"valid,omitempty"`
	CADERSHA256   string `json:"ca_der_sha256"`
	Created       bool   `json:"created,omitempty"`
}

var roleFiles = map[string][]string{"operator": {"ca.pem", "ca-key.pem"}, "server": {"ca.pem", "server-chain.pem", "server-key.pem", "reachd.json"}, "client": {"client.reachidentity"}}
var roles = []string{"operator", "server", "client"}

func Create(r Request, output string) (Result, error) { return createAt(r, output, time.Now(), nil) }

// afterWrite is an internal fault/crash-test seam; the executable has no override.
func createAt(r Request, output string, now time.Time, afterWrite func(string) error) (Result, error) {
	return createWith(r, output, now, afterWrite, writeFile)
}

func createWith(r Request, output string, now time.Time, afterWrite func(string) error, write func(*os.Root, string, []byte) error) (Result, error) {
	if err := requireOperator(); err != nil {
		return Result{}, err
	}
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	if err := canonical(output, false); err != nil {
		return Result{}, err
	}
	if err := privateDirectory(filepath.Dir(output)); err != nil {
		return Result{}, err
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return Result{}, err
	}
	if err := os.Chmod(output, 0700); err != nil {
		return Result{}, err
	}
	root, err := os.OpenRoot(output)
	if err != nil {
		return Result{}, err
	}
	defer root.Close()
	for _, role := range roles {
		if err := root.Mkdir(role, 0700); err != nil {
			return Result{}, err
		}
		if err := root.Chmod(role, 0700); err != nil {
			return Result{}, err
		}
	}
	keys, err := issue(r, now)
	if err != nil {
		return Result{}, err
	}
	caKey, err := privatePEM(keys.caKey)
	if err != nil {
		return Result{}, err
	}
	serverKey, err := privatePEM(keys.serverKey)
	if err != nil {
		return Result{}, err
	}
	client, err := json.MarshalIndent(clientBundle{r.ClusterName, keys.ca, keys.client, x963(keys.clientKey)}, "", "  ")
	if err != nil {
		return Result{}, err
	}
	service, err := json.MarshalIndent(r.service(), "", "  ")
	if err != nil {
		return Result{}, err
	}
	files := map[string][]byte{"operator/ca.pem": certificatePEM(keys.ca), "operator/ca-key.pem": caKey, "server/ca.pem": certificatePEM(keys.ca), "server/server-chain.pem": append(certificatePEM(keys.server), certificatePEM(keys.ca)...), "server/server-key.pem": serverKey, "server/reachd.json": append(service, '\n'), "client/client.reachidentity": append(client, '\n')}
	for _, role := range roles {
		for _, name := range roleFiles[role] {
			path := role + "/" + name
			if err := write(root, path, files[path]); err != nil {
				return Result{}, err
			}
			if afterWrite != nil {
				if err := afterWrite(path); err != nil {
					return Result{}, err
				}
			}
		}
		if err := syncDirectory(filepath.Join(output, role)); err != nil {
			return Result{}, err
		}
	}
	if err := syncDirectory(output); err != nil {
		return Result{}, err
	}
	if err := syncDirectory(filepath.Dir(output)); err != nil {
		return Result{}, err
	}
	return Result{SchemaVersion: 1, CADERSHA256: fingerprint(keys.ca), Created: true}, nil
}
