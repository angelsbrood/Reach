// Package mtls builds mutually authenticated transports from operator-owned files.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"reach.dev/exo-runtime/internal/config"
)

func Client(files config.TLSFiles, serverName string) (*tls.Config, error) {
	certificate, roots, err := load(files)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		ServerName:   serverName,
	}, nil
}

func Server(files config.TLSFiles, clientName string) (*tls.Config, error) {
	certificate, roots, err := load(files)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return errors.New("exactly one peer certificate is required")
			}
			peer := state.PeerCertificates[0]
			if peer.Subject.CommonName != clientName {
				return fmt.Errorf("peer common name %q is not %q", peer.Subject.CommonName, clientName)
			}
			return nil
		},
	}, nil
}

func load(files config.TLSFiles) (tls.Certificate, *x509.CertPool, error) {
	certificate, err := tls.LoadX509KeyPair(files.Certificate, files.PrivateKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("load certificate pair: %w", err)
	}
	caBytes, err := os.ReadFile(files.CA)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("read CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return tls.Certificate{}, nil, errors.New("CA file contains no certificates")
	}
	return certificate, roots, nil
}
