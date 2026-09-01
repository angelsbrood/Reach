// Package gateway provides the only authenticated cluster-side HTTP publication.
package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"reach.dev/exo-runtime/internal/authority"
)

const maxRequestBytes = 4 * 1024 * 1024

func AllowedRequest(request *http.Request) bool {
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/v1/models":
		return request.URL.RawQuery == ""
	case request.Method == http.MethodPost && request.URL.Path == "/v1/chat/completions":
		return request.URL.RawQuery == "" && (request.ContentLength < 0 || request.ContentLength <= maxRequestBytes)
	default:
		return false
	}
}

func Handler(transport http.RoundTripper, target *url.URL, epoch string) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	proxy.FlushInterval = -1
	original := proxy.Director
	proxy.Director = func(request *http.Request) {
		original(request)
		request.Header.Del("Authorization")
		request.Header.Del("Proxy-Authorization")
		request.Header.Set("X-Reach-EXO-Epoch", epoch)
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(writer, "provider unavailable", http.StatusServiceUnavailable)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !AllowedRequest(request) {
			http.Error(writer, "route not published", http.StatusNotFound)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
		proxy.ServeHTTP(writer, request)
	})
}

type Server struct {
	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
}

func (s *Server) Address() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) Start(address string, tlsConfig *tls.Config, handler http.Handler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != nil {
		return errors.New("gateway already published")
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(listener, tlsConfig)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 * 1024,
	}
	s.listener = tlsListener
	s.server = server
	go func() {
		_ = server.Serve(tlsListener)
	}()
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	server := s.server
	listener := s.listener
	s.server = nil
	s.listener = nil
	s.mu.Unlock()
	if server == nil {
		return nil
	}
	if listener != nil {
		_ = listener.Close()
	}
	if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("close gateway: %w", err)
	}
	return nil
}

func LocalTransport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
	}
}

func TLSTransport(config *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		TLSClientConfig:     config,
		ForceAttemptHTTP2:   false,
		DisableCompression:  true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
	}
}

func LocalTarget() *url.URL {
	return &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", authority.ProviderAPIPort)}
}

func Shutdown(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}
