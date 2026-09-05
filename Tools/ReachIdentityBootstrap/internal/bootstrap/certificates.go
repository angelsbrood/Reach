package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

func guardedKey(generate func() (*ecdsa.PrivateKey, error)) (*ecdsa.PrivateKey, error) {
	for {
		key, err := generate()
		if err != nil {
			return nil, err
		}
		if key.D.FillBytes(make([]byte, 32))[0] != 0 {
			return key, nil
		}
	}
}

func mintKey() (*ecdsa.PrivateKey, error) {
	return guardedKey(func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) })
}

func fingerprint(der []byte) string { h := sha256.Sum256(der); return hex.EncodeToString(h[:]) }
func certificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func privatePEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
func x963(key *ecdsa.PrivateKey) []byte {
	return append(elliptic.Marshal(elliptic.P256(), key.X, key.Y), key.D.FillBytes(make([]byte, 32))...)
}

func serverIPs(r Request) []net.IP {
	seen := map[string]bool{}
	var ips []net.IP
	for _, e := range append([]Endpoint{r.Listen}, r.AdvertisedRoads...) {
		if e.Address != "0.0.0.0" && !seen[e.Address] {
			seen[e.Address] = true
			ips = append(ips, net.ParseIP(e.Address).To4())
		}
	}
	return ips
}

type issued struct {
	ca, server, client          []byte
	caKey, serverKey, clientKey *ecdsa.PrivateKey
}

func issue(r Request, now time.Time) (issued, error) {
	var out issued
	var err error
	out.caKey, err = mintKey()
	if err != nil {
		return out, err
	}
	out.serverKey, err = mintKey()
	if err != nil {
		return out, err
	}
	out.clientKey, err = mintKey()
	if err != nil {
		return out, err
	}
	v := r.validity()
	now = now.UTC().Truncate(time.Second)
	serials := map[string]bool{}
	serial := func() (*big.Int, error) {
		for {
			n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
			if err != nil {
				return nil, err
			}
			if n.Sign() > 0 && !serials[n.String()] {
				serials[n.String()] = true
				return n, nil
			}
		}
	}
	template := func(name string, seconds int64) (*x509.Certificate, error) {
		n, err := serial()
		if err != nil {
			return nil, err
		}
		return &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Duration(seconds) * time.Second), SignatureAlgorithm: x509.ECDSAWithSHA256}, nil
	}
	ca, err := template(r.ClusterName, v.CA)
	if err != nil {
		return out, err
	}
	ca.IsCA = true
	ca.BasicConstraintsValid = true
	ca.MaxPathLen = 0
	ca.MaxPathLenZero = true
	ca.KeyUsage = x509.KeyUsageCertSign
	out.ca, err = x509.CreateCertificate(rand.Reader, ca, ca, &out.caKey.PublicKey, out.caKey)
	if err != nil {
		return out, err
	}
	server, err := template("localhost", v.Server)
	if err != nil {
		return out, err
	}
	server.KeyUsage = x509.KeyUsageDigitalSignature
	server.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	server.DNSNames = []string{"localhost"}
	server.IPAddresses = serverIPs(r)
	out.server, err = x509.CreateCertificate(rand.Reader, server, ca, &out.serverKey.PublicKey, out.caKey)
	if err != nil {
		return out, err
	}
	client, err := template(r.ClientName, v.Client)
	if err != nil {
		return out, err
	}
	u, _ := url.Parse("reach://device/" + strings.ToLower(r.ClientID))
	client.KeyUsage = x509.KeyUsageDigitalSignature
	client.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	client.URIs = []*url.URL{u}
	out.client, err = x509.CreateCertificate(rand.Reader, client, ca, &out.clientKey.PublicKey, out.caKey)
	return out, err
}
