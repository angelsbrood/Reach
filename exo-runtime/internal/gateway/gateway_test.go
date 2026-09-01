package gateway

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAllowedRequestSurface(t *testing.T) {
	tests := []struct {
		method string
		path   string
		query  string
		length int64
		want   bool
	}{
		{http.MethodGet, "/v1/models", "", 0, true},
		{http.MethodPost, "/v1/chat/completions", "", 100, true},
		{http.MethodGet, "/v1/chat/completions", "", 0, false},
		{http.MethodGet, "/state", "", 0, false},
		{http.MethodGet, "/events", "", 0, false},
		{http.MethodPost, "/instance", "", 10, false},
		{http.MethodGet, "/v1/models", "x=1", 0, false},
		{http.MethodPost, "/v1/chat/completions", "", maxRequestBytes + 1, false},
	}
	for _, test := range tests {
		request := &http.Request{Method: test.method, URL: &url.URL{Path: test.path, RawQuery: test.query}, ContentLength: test.length}
		if got := AllowedRequest(request); got != test.want {
			t.Fatalf("%s %s: got %v want %v", test.method, test.path, got, test.want)
		}
	}
}

func TestCloseWithdrawsListenerAndActiveStream(t *testing.T) {
	certificate := testCertificate(t)
	release := make(chan struct{})
	started := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		flusher := writer.(http.Flusher)
		_, _ = writer.Write([]byte("ready\n"))
		flusher.Flush()
		close(started)
		<-release
	})
	server := &Server{}
	if err := server.Start("127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, handler); err != nil {
		t.Fatal(err)
	}
	address := server.Address()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+address+"/", nil)
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("initial stream read %q, %v", line, err)
	}
	<-started
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("active stream survived withdrawal")
	}
	dialer := net.Dialer{Timeout: 100 * time.Millisecond}
	if connection, err := dialer.Dial("tcp4", address); err == nil {
		connection.Close()
		t.Fatal("listener survived withdrawal")
	}
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0), DNSNames: []string{"test"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestAllowedRequestRejectsRouteConfusion(t *testing.T) {
	for _, path := range []string{"//v1/models", "/v1/models/", "/v1/models%2f..%2fstate", "/V1/models", "/v1/chat/completions/"} {
		request := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: path}, ContentLength: int64(len(strings.Repeat("x", 1)))}
		if AllowedRequest(request) {
			t.Fatalf("route confusion %q was accepted", path)
		}
	}
}
