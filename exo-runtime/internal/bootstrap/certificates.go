package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"time"
)

type issuedCertificate struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Certificate    *x509.Certificate
	PrivateKey     *ecdsa.PrivateKey
	Fingerprint    string
}

type certificateSet struct {
	CA          issuedCertificate
	Coordinator issuedCertificate
	Worker      issuedCertificate
	Connector   issuedCertificate
}

func issueCertificates(reader io.Reader, createdAt, expiresAt time.Time, authorityID string) (certificateSet, error) {
	if reader == nil {
		reader = cryptorand.Reader
	}
	createdAt = createdAt.UTC().Truncate(time.Second)
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), reader)
	if err != nil {
		return certificateSet{}, err
	}
	caSerial, err := randomSerial(reader)
	if err != nil {
		return certificateSet{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial, Subject: pkix.Name{CommonName: "reach-exo-bootstrap-ca-" + authorityID[:16]},
		NotBefore: createdAt.Add(-5 * time.Minute), NotAfter: expiresAt,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	ca, err := marshalCertificate(reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return certificateSet{}, err
	}
	coordinator, err := issueLeaf(reader, createdAt, expiresAt, ca.Certificate, caKey, "reach-exo-coordinator", []string{"reach-exo-gateway"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
	if err != nil {
		return certificateSet{}, err
	}
	worker, err := issueLeaf(reader, createdAt, expiresAt, ca.Certificate, caKey, "reach-exo-worker", []string{"reach-exo-worker"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return certificateSet{}, err
	}
	connector, err := issueLeaf(reader, createdAt, expiresAt, ca.Certificate, caKey, "reach-exo-connector", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		return certificateSet{}, err
	}
	serials := map[string]bool{}
	for _, certificate := range []*x509.Certificate{ca.Certificate, coordinator.Certificate, worker.Certificate, connector.Certificate} {
		serial := certificate.SerialNumber.Text(16)
		if serials[serial] {
			return certificateSet{}, errors.New("certificate serial collision")
		}
		serials[serial] = true
	}
	return certificateSet{CA: ca, Coordinator: coordinator, Worker: worker, Connector: connector}, nil
}

func issueLeaf(reader io.Reader, createdAt, expiresAt time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, dnsNames []string, usages []x509.ExtKeyUsage) (issuedCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), reader)
	if err != nil {
		return issuedCertificate{}, err
	}
	serial, err := randomSerial(reader)
	if err != nil {
		return issuedCertificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
		NotBefore: createdAt.Add(-5 * time.Minute), NotAfter: expiresAt,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages,
		BasicConstraintsValid: true, IsCA: false, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	return marshalCertificate(reader, template, ca, &key.PublicKey, caKey, key)
}

func marshalCertificate(reader io.Reader, template, parent *x509.Certificate, publicKey any, signer *ecdsa.PrivateKey, privateKeys ...*ecdsa.PrivateKey) (issuedCertificate, error) {
	der, err := x509.CreateCertificate(reader, template, parent, publicKey, signer)
	if err != nil {
		return issuedCertificate{}, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return issuedCertificate{}, err
	}
	privateKey := signer
	if len(privateKeys) == 1 {
		privateKey = privateKeys[0]
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return issuedCertificate{}, err
	}
	digest := sha256.Sum256(der)
	return issuedCertificate{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Certificate:    certificate, PrivateKey: privateKey, Fingerprint: hex.EncodeToString(digest[:]),
	}, nil
}

func randomSerial(reader io.Reader) (*big.Int, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return nil, err
	}
	bytes[0] |= 0x80
	serial := new(big.Int).SetBytes(bytes)
	if serial.Sign() <= 0 {
		return nil, errors.New("random serial is not positive")
	}
	return serial, nil
}
