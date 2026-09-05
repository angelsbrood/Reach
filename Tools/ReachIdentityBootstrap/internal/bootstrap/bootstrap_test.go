package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func request() Request {
	return Request{SchemaVersion: 1, ClusterName: "Reach test cluster", ClientName: "Test client", ClientID: "ABCD1234-1234-1234-1234-123456789ABC", Listen: Endpoint{"127.0.0.1", 48660}, AdvertisedRoads: []Endpoint{{"127.0.0.1", 48660}}, ModelID: "reach-s66-synthetic-model", EXOEndpoint: "http://127.0.0.1:48663"}
}

func parent(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixture(t *testing.T) (Request, string, Result, time.Time) {
	t.Helper()
	r := request()
	root := filepath.Join(parent(t), "bundle")
	now := time.Now().UTC().Truncate(time.Second)
	result, err := createAt(r, root, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAt(r, root, result.CADERSHA256, now); err != nil {
		t.Fatal(err)
	}
	return r, root, result, now
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func put(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestProfileFormatAndServiceContract(t *testing.T) {
	r, root, result, now := fixture(t)
	if !result.Created || result.Valid {
		t.Fatal("create must not claim independent verification")
	}
	ca, err := parseCertificates(read(t, filepath.Join(root, "operator/ca.pem")), 1)
	if err != nil {
		t.Fatal(err)
	}
	c := ca[0]
	if c.Subject.CommonName != r.ClusterName || !c.MaxPathLenZero || c.MaxPathLen != 0 || c.KeyUsage != x509.KeyUsageCertSign || !c.NotBefore.Equal(now.Add(-time.Hour)) || !c.NotAfter.Equal(now.Add(730*24*time.Hour)) {
		t.Fatal("root contract differs")
	}
	var client clientBundle
	if err := strictJSON(read(t, filepath.Join(root, "client/client.reachidentity")), 32768, &client); err != nil {
		t.Fatal(err)
	}
	if len(client.PrivateKeyX963) != 97 || client.PrivateKeyX963[65] == 0 {
		t.Fatal("X9.63 width guard differs")
	}
	leaf, err := x509.ParseCertificate(client.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.URIs[0].String() != "reach://device/abcd1234-1234-1234-1234-123456789abc" || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || !leaf.NotAfter.Equal(now.Add(365*24*time.Hour)) {
		t.Fatal("manual client contract differs")
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(read(t, filepath.Join(root, "client/client.reachidentity")), &fields)
	if len(fields) != 4 {
		t.Fatal("existing client format has extra fields")
	}
	service := r.service()
	if service.SchemaVersion != 1 || service.TLS.CA != "/etc/reach/tls/ca.pem" || service.TLS.Key != "/etc/reach/tls/server-key.pem" {
		t.Fatal("service projection differs")
	}
	if _, err := verifyAt(r, root, result.CADERSHA256, now); err != nil {
		t.Fatal(err)
	}
}

func TestShortValidityAndWildcardSANs(t *testing.T) {
	r := request()
	r.ValiditySeconds = &Validity{7200, 1200, 3600}
	r.Listen.Address = "0.0.0.0"
	r.AdvertisedRoads = []Endpoint{{"127.0.0.1", 48660}, {"192.168.42.1", 48660}}
	root := filepath.Join(parent(t), "bundle")
	now := time.Now().UTC().Truncate(time.Second)
	result, err := createAt(r, root, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAt(r, root, result.CADERSHA256, now); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAt(r, root, result.CADERSHA256, now.Add(1200*time.Second)); err == nil {
		t.Fatal("expired server accepted")
	}
	if _, err := verifyAt(r, root, result.CADERSHA256, now.Add(-time.Hour-time.Second)); err == nil {
		t.Fatal("not-yet-valid certificate accepted")
	}
}

func TestLeadingZeroScalarIsRejectedBeforeIssuance(t *testing.T) {
	makeKey := func(d *big.Int) *ecdsa.PrivateKey {
		x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
		return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	}
	short := makeKey(big.NewInt(1))
	full := makeKey(new(big.Int).Lsh(big.NewInt(1), 248))
	calls := 0
	k, err := guardedKey(func() (*ecdsa.PrivateKey, error) {
		calls++
		if calls == 1 {
			return short, nil
		}
		return full, nil
	})
	if err != nil || calls != 2 || k != full {
		t.Fatal("known leading-zero scalar was not replaced")
	}
	pem, err := privatePEM(short)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseKey(pem); err == nil {
		t.Fatal("persisted short scalar accepted")
	}
	want := errors.New("entropy unavailable")
	if _, err := guardedKey(func() (*ecdsa.PrivateKey, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal("key generation error lost")
	}
}

func TestEXOEndpointMatchesServiceConsumer(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		valid    bool
	}{
		{"http://127.0.0.1:48663", true},
		{"http://127.0.0.1:1024", true},
		{"http://127.0.0.1:65535", true},
		{"http://127.0.0.2:48663", false},
		{"http://127.1.2.3:48663", false},
		{"http://127.255.255.254:48663", false},
		{"http://127.0.0.1:1023", false},
		{"http://127.0.0.1:65536", false},
		{"http://127.0.0.1:048663", false},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			r := request()
			r.EXOEndpoint = tc.endpoint
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeRequest(data)
			if (err == nil) != tc.valid {
				t.Fatalf("endpoint accepted = %t, want %t", err == nil, tc.valid)
			}
			if tc.valid && decoded.service().EXOEndpoint != tc.endpoint {
				t.Fatal("accepted service endpoint changed")
			}
		})
	}
}

func TestStrictRequestRefusals(t *testing.T) {
	valid, _ := json.Marshal(request())
	for name, data := range map[string][]byte{
		"duplicate":        bytes.Replace(valid, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1,"schemaVersion":1`), 1),
		"nested duplicate": bytes.Replace(valid, []byte(`"port":48660`), []byte(`"port":48660,"port":48660`), 1),
		"case alias":       bytes.Replace(valid, []byte(`"clusterName"`), []byte(`"ClusterName"`), 1),
		"unknown":          append([]byte(`{"unknown":true,`), valid[1:]...),
		"trailing":         append(append([]byte{}, valid...), []byte(` {}`)...),
		"null":             bytes.Replace(valid, []byte(`"Reach test cluster"`), []byte(`null`), 1),
		"missing":          []byte(`{}`), "oversized": bytes.Repeat([]byte(" "), MaximumRequestBytes+1), "malformed": []byte(`{"schemaVersion":`), "invalid utf8": {0xff},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(data); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	mutations := map[string]func(*Request){
		"schema": func(r *Request) { r.SchemaVersion = 2 }, "uuid": func(r *Request) { r.ClientID = "device" }, "unicode": func(r *Request) { r.ClusterName = "café" }, "control": func(r *Request) { r.ClientName = "bad\nname" }, "large model": func(r *Request) { r.ModelID = strings.Repeat("x", 257) },
		"DNS listener": func(r *Request) { r.Listen.Address = "localhost" }, "IPv6": func(r *Request) { r.Listen.Address = "::1" }, "noncanonical IP": func(r *Request) { r.Listen.Address = "127.00.0.1" }, "privileged port": func(r *Request) { r.Listen.Port = 80 }, "port overflow": func(r *Request) { r.Listen.Port = 65536 }, "wildcard road": func(r *Request) { r.AdvertisedRoads[0].Address = "0.0.0.0" }, "duplicate road": func(r *Request) { r.AdvertisedRoads = append(r.AdvertisedRoads, r.AdvertisedRoads[0]) }, "no road": func(r *Request) { r.AdvertisedRoads = nil },
		"remote EXO": func(r *Request) { r.EXOEndpoint = "http://192.168.1.1:48663" }, "EXO DNS": func(r *Request) { r.EXOEndpoint = "http://localhost:48663" }, "EXO path": func(r *Request) { r.EXOEndpoint += "/v1" }, "EXO credentials": func(r *Request) { r.EXOEndpoint = "http://user@127.0.0.1:48663" }, "EXO query": func(r *Request) { r.EXOEndpoint += "?x=1" },
		"zero validity": func(r *Request) { r.ValiditySeconds = &Validity{} }, "negative validity": func(r *Request) { r.ValiditySeconds = &Validity{1, -1, 1} }, "leaf beyond root": func(r *Request) { r.ValiditySeconds = &Validity{60, 120, 60} }, "too long": func(r *Request) { r.ValiditySeconds = &Validity{730*86400 + 1, 60, 60} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := request()
			mutate(&r)
			data, _ := json.Marshal(r)
			if _, err := DecodeRequest(data); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	r, err := DecodeRequest(valid)
	if err != nil || r.ClientID != strings.ToLower(request().ClientID) {
		t.Fatal("valid request or UUID normalization failed")
	}
}

func TestVerifierRejectsTamperingAndMismatchedRequest(t *testing.T) {
	for _, name := range []string{"wrong root", "malformed digest", "changed config", "missing", "extra", "swapped key", "swapped cert", "malformed key", "skipped malformed key PEM", "skipped malformed certificate PEM", "client public mismatch", "client leading zero", "client root", "client unknown", "request model", "request UUID", "request duration"} {
		t.Run(name, func(t *testing.T) {
			r, root, result, now := fixture(t)
			expected := result.CADERSHA256
			switch name {
			case "wrong root":
				expected = strings.Repeat("0", 64)
			case "malformed digest":
				expected = "BAD"
			case "changed config":
				put(t, filepath.Join(root, "server/reachd.json"), []byte(`{}`))
			case "missing":
				os.Remove(filepath.Join(root, "server/server-key.pem"))
			case "extra":
				put(t, filepath.Join(root, "operator/extra"), []byte("x"))
			case "swapped key":
				put(t, filepath.Join(root, "server/server-key.pem"), read(t, filepath.Join(root, "operator/ca-key.pem")))
			case "swapped cert":
				put(t, filepath.Join(root, "server/server-chain.pem"), append(read(t, filepath.Join(root, "operator/ca.pem")), read(t, filepath.Join(root, "operator/ca.pem"))...))
			case "malformed key":
				put(t, filepath.Join(root, "operator/ca-key.pem"), []byte("invalid"))
			case "skipped malformed key PEM":
				path := filepath.Join(root, "operator/ca-key.pem")
				put(t, path, append([]byte("-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----\n"), read(t, path)...))
			case "skipped malformed certificate PEM":
				path := filepath.Join(root, "server/server-chain.pem")
				put(t, path, append([]byte("-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n"), read(t, path)...))
			case "client public mismatch", "client leading zero", "client root", "client unknown":
				path := filepath.Join(root, "client/client.reachidentity")
				var c clientBundle
				json.Unmarshal(read(t, path), &c)
				if name == "client public mismatch" {
					c.PrivateKeyX963[1] ^= 1
				}
				if name == "client leading zero" {
					c.PrivateKeyX963[65] = 0
				}
				if name == "client root" {
					c.CACertificateDER = c.CertificateDER
				}
				data, _ := json.Marshal(c)
				if name == "client unknown" {
					data = append([]byte(`{"extra":1,`), data[1:]...)
				}
				put(t, path, data)
			case "request model":
				r.ModelID = "different"
			case "request UUID":
				r.ClientID = "00000000-0000-0000-0000-000000000000"
			case "request duration":
				r.ValiditySeconds = &Validity{7200, 1200, 3600}
			}
			if _, err := verifyAt(r, root, expected, now); err == nil {
				t.Fatal("tampered bundle accepted")
			}
		})
	}
}

func TestSignedWrongServerProfilesRefuse(t *testing.T) {
	for _, name := range []string{"wrong EKU", "extra EKU", "missing SAN", "wrong SAN", "CA leaf", "wrong usage", "wrong subject", "wrong validity"} {
		t.Run(name, func(t *testing.T) {
			r, root, result, now := fixture(t)
			ca, _ := parseCertificates(read(t, filepath.Join(root, "operator/ca.pem")), 1)
			chain, _ := parseCertificates(read(t, filepath.Join(root, "server/server-chain.pem")), 2)
			caKey, _ := parseKey(read(t, filepath.Join(root, "operator/ca-key.pem")))
			key, _ := parseKey(read(t, filepath.Join(root, "server/server-key.pem")))
			leaf := chain[0]
			switch name {
			case "wrong EKU":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			case "extra EKU":
				leaf.ExtKeyUsage = append(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
			case "missing SAN":
				leaf.DNSNames = nil
				leaf.IPAddresses = nil
			case "wrong SAN":
				leaf.DNSNames = []string{"other"}
			case "CA leaf":
				leaf.BasicConstraintsValid = true
				leaf.IsCA = true
			case "wrong usage":
				leaf.KeyUsage = x509.KeyUsageKeyEncipherment
			case "wrong subject":
				leaf.Subject.CommonName = "other"
				leaf.RawSubject = nil
			case "wrong validity":
				leaf.NotAfter = leaf.NotAfter.Add(time.Second)
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, ca[0], &key.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			put(t, filepath.Join(root, "server/server-chain.pem"), append(certificatePEM(der), certificatePEM(ca[0].Raw)...))
			if _, err := verifyAt(r, root, result.CADERSHA256, now); err == nil {
				t.Fatal("signed wrong-role/profile leaf accepted")
			}
		})
	}
}
