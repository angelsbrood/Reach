package bootstrap

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func Verify(r Request, bundle, expected string) (Result, error) {
	return verifyAt(r, bundle, expected, time.Now())
}

func verifyAt(r Request, bundle, expected string, now time.Time) (Result, error) {
	if err := requireOperator(); err != nil {
		return Result{}, err
	}
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	if !digestPattern.MatchString(expected) {
		return Result{}, errors.New("expected CA must be an external lowercase SHA-256 digest")
	}
	if err := exactEntries(bundle, roles); err != nil {
		return Result{}, err
	}
	files := map[string][]byte{}
	for _, role := range roles {
		if err := exactEntries(filepath.Join(bundle, role), roleFiles[role]); err != nil {
			return Result{}, err
		}
		for _, name := range roleFiles[role] {
			path := role + "/" + name
			data, err := readPrivate(filepath.Join(bundle, path), 32768)
			if err != nil {
				return Result{}, err
			}
			files[path] = data
		}
	}
	ca, err := parseCertificates(files["operator/ca.pem"], 1)
	if err != nil {
		return Result{}, err
	}
	root := ca[0]
	if fingerprint(root.Raw) != expected {
		return Result{}, errors.New("CA fingerprint mismatch")
	}
	if !bytes.Equal(files["server/ca.pem"], files["operator/ca.pem"]) {
		return Result{}, errors.New("server root differs")
	}
	chain, err := parseCertificates(files["server/server-chain.pem"], 2)
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(chain[1].Raw, root.Raw) {
		return Result{}, errors.New("server chain root differs")
	}
	server := chain[0]
	caKey, err := parseKey(files["operator/ca-key.pem"])
	if err != nil {
		return Result{}, err
	}
	serverKey, err := parseKey(files["server/server-key.pem"])
	if err != nil {
		return Result{}, err
	}
	var client clientBundle
	if err := strictJSON(files["client/client.reachidentity"], 32768, &client); err != nil {
		return Result{}, err
	}
	if client.ClusterName != r.ClusterName || !bytes.Equal(client.CACertificateDER, root.Raw) {
		return Result{}, errors.New("client cluster or root differs")
	}
	leaf, err := x509.ParseCertificate(client.CertificateDER)
	if err != nil {
		return Result{}, errors.New("invalid client certificate")
	}
	if len(client.PrivateKeyX963) != 97 || client.PrivateKeyX963[0] != 4 || client.PrivateKeyX963[65] == 0 {
		return Result{}, errors.New("invalid or short-width client X9.63 key")
	}
	clientKey, err := ecdh.P256().NewPrivateKey(client.PrivateKeyX963[65:])
	if err != nil || !bytes.Equal(clientKey.PublicKey().Bytes(), client.PrivateKeyX963[:65]) {
		return Result{}, errors.New("X9.63 public/private mismatch")
	}
	if !matches(root, &caKey.PublicKey) || !matches(server, &serverKey.PublicKey) || !bytes.Equal(publicBytes(leaf), clientKey.PublicKey().Bytes()) {
		return Result{}, errors.New("certificate/key correspondence mismatch")
	}
	if bytes.Equal(publicBytes(root), publicBytes(server)) || bytes.Equal(publicBytes(root), publicBytes(leaf)) || bytes.Equal(publicBytes(server), publicBytes(leaf)) {
		return Result{}, errors.New("role keys must be distinct")
	}
	if root.SerialNumber.Cmp(server.SerialNumber) == 0 || root.SerialNumber.Cmp(leaf.SerialNumber) == 0 || server.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
		return Result{}, errors.New("role serials must be distinct")
	}
	var service serviceConfig
	if err := strictJSON(files["server/reachd.json"], 32768, &service); err != nil {
		return Result{}, err
	}
	if !reflect.DeepEqual(service, r.service()) {
		return Result{}, errors.New("service configuration differs from request")
	}
	v := r.validity()
	issued := root.NotBefore.Add(time.Hour)
	for _, pair := range []struct {
		cert    *x509.Certificate
		seconds int64
	}{{root, v.CA}, {server, v.Server}, {leaf, v.Client}} {
		c := pair.cert
		if !c.NotBefore.Equal(root.NotBefore) || !c.NotAfter.Equal(issued.Add(time.Duration(pair.seconds)*time.Second)) || now.Before(c.NotBefore) || !now.Before(c.NotAfter) || c.NotAfter.After(root.NotAfter) {
			return Result{}, errors.New("certificate validity differs or is not current")
		}
		if c.Version != 3 || c.SignatureAlgorithm != x509.ECDSAWithSHA256 || c.SerialNumber.Sign() <= 0 || len(c.SerialNumber.Bytes()) > 20 || len(publicBytes(c)) != 65 {
			return Result{}, errors.New("certificate algorithm or serial differs")
		}
	}
	if !singleName(root, r.ClusterName) || !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil || !root.IsCA || !root.BasicConstraintsValid || root.MaxPathLen != 0 || !root.MaxPathLenZero || root.KeyUsage != x509.KeyUsageCertSign || len(root.ExtKeyUsage) != 0 || hasSAN(root) {
		return Result{}, errors.New("root profile or self-signature differs")
	}
	if err := extensions(root, true); err != nil {
		return Result{}, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	for _, pair := range []struct {
		cert  *x509.Certificate
		usage x509.ExtKeyUsage
		name  string
	}{{server, x509.ExtKeyUsageServerAuth, "localhost"}, {leaf, x509.ExtKeyUsageClientAuth, r.ClientName}} {
		c := pair.cert
		if !singleName(c, pair.name) || !bytes.Equal(c.RawIssuer, root.RawSubject) || c.IsCA || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != pair.usage || len(c.UnknownExtKeyUsage) != 0 {
			return Result{}, errors.New("leaf subject or role differs")
		}
		if err := extensions(c, false); err != nil {
			return Result{}, err
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{pair.usage}}); err != nil {
			return Result{}, errors.New("leaf chain or intended EKU verification failed")
		}
	}
	if !reflect.DeepEqual(server.DNSNames, []string{"localhost"}) || len(server.URIs) != 0 || len(server.EmailAddresses) != 0 || len(server.IPAddresses) != len(serverIPs(r)) {
		return Result{}, errors.New("server SAN profile differs")
	}
	for i, ip := range serverIPs(r) {
		if !ip.Equal(server.IPAddresses[i]) {
			return Result{}, errors.New("server IP SAN differs")
		}
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "reach://device/"+strings.ToLower(r.ClientID) || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return Result{}, errors.New("client URI SAN differs")
	}
	return Result{SchemaVersion: 1, Valid: true, CADERSHA256: expected}, nil
}

func parseCertificates(data []byte, count int) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(data) > 0 {
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("invalid certificate PEM framing")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate PEM")
		}
		// pem.Decode can silently skip a malformed block before a valid one.
		// A bundle contains the canonical PEM emitted by this tool, without junk.
		if !bytes.Equal(data[:len(data)-len(rest)], pem.EncodeToMemory(block)) {
			return nil, errors.New("noncanonical or skipped certificate PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid certificate DER")
		}
		out = append(out, c)
		if len(out) > count {
			return nil, errors.New("extra certificate")
		}
		data = rest
	}
	if len(out) != count {
		return nil, errors.New("missing certificate")
	}
	return out, nil
}

func parseKey(data []byte) (*ecdsa.PrivateKey, error) {
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, errors.New("invalid private key framing")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, errors.New("invalid private key PEM")
	}
	if !bytes.Equal(data, pem.EncodeToMemory(block)) {
		return nil, errors.New("noncanonical or skipped private key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid private key DER")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() || key.D.FillBytes(make([]byte, 32))[0] == 0 {
		return nil, errors.New("key must be full-width P-256")
	}
	derived, err := ecdh.P256().NewPrivateKey(key.D.FillBytes(make([]byte, 32)))
	if err != nil || !bytes.Equal(derived.PublicKey().Bytes(), elliptic.Marshal(elliptic.P256(), key.X, key.Y)) {
		return nil, errors.New("private key correspondence differs")
	}
	return key, nil
}

func publicBytes(c *x509.Certificate) []byte {
	k, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil
	}
	return elliptic.Marshal(elliptic.P256(), k.X, k.Y)
}
func matches(c *x509.Certificate, k *ecdsa.PublicKey) bool {
	return bytes.Equal(publicBytes(c), elliptic.Marshal(elliptic.P256(), k.X, k.Y))
}
func singleName(c *x509.Certificate, name string) bool {
	return c.Subject.CommonName == name && len(c.Subject.Names) == 1 && c.Subject.Names[0].Type.String() == "2.5.4.3"
}
func hasSAN(c *x509.Certificate) bool {
	return len(c.DNSNames)+len(c.IPAddresses)+len(c.URIs)+len(c.EmailAddresses) > 0
}

func extensions(c *x509.Certificate, root bool) error {
	required := map[string]bool{"2.5.29.15": true}
	allowed := map[string]bool{"2.5.29.15": true, "2.5.29.14": true, "2.5.29.35": true}
	if root {
		required["2.5.29.19"] = true
		allowed["2.5.29.19"] = true
	} else {
		required["2.5.29.37"] = true
		required["2.5.29.17"] = true
		allowed["2.5.29.37"] = true
		allowed["2.5.29.17"] = true
	}
	seen := map[string]bool{}
	for _, e := range c.Extensions {
		id := e.Id.String()
		critical := id == "2.5.29.15" || id == "2.5.29.19"
		if !allowed[id] || seen[id] || e.Critical != critical {
			return errors.New("certificate extension profile differs")
		}
		seen[id] = true
	}
	for id := range required {
		if !seen[id] {
			return errors.New("required certificate extension is absent")
		}
	}
	return nil
}
