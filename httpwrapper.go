package httpwrapper

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Request struct {
	Params map[string]string
	Header http.Header
	Query  url.Values
	Body   interface{}
	URL    *url.URL
}

func NewRequest(req *http.Request, body interface{}) *Request {
	ret := &Request{}
	ret.Query = req.URL.Query()
	ret.Header = req.Header
	ret.Body = body
	ret.Params = make(map[string]string)
	ret.URL = req.URL
	return ret
}

type Response struct {
	Header http.Header
	Status int
	Body   interface{}
}

func NewResponse(code int, h http.Header, body interface{}) *Response {
	ret := &Response{}
	ret.Status = code
	ret.Header = h
	ret.Body = body
	return ret
}

// NewHttp2Server returns a server instance with HTTP/2.0 and HTTP/2.0 cleartext support
// If this function cannot open or create the secret log file,
// **it still returns server instance** but without the secret log and error indication
func NewHttp2Server(bindAddr string, preMasterSecretLogPath string, handler http.Handler, certKeyPaths []struct{Cert, Key string },) (*http.Server, error) {
	if handler == nil {
		return nil, errors.New("server needs handler to handle request")
	}

	h2Server := &http2.Server{
		// TODO: extends the idle time after re-use openapi client
		IdleTimeout: 1 * time.Millisecond,
	}
	server := &http.Server{
		Addr:    bindAddr,
		Handler: h2c.NewHandler(handler, h2Server),
	}

	tlsConfig := &tls.Config{
		PQSignatureSchemesEnabled: true,
	}

	if preMasterSecretLogPath != "" {
		preMasterSecretFile, err := os.OpenFile(preMasterSecretLogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create pre-master-secret log [%s] fail: %s", preMasterSecretLogPath, err)
		}
		tlsConfig.KeyLogWriter = preMasterSecretFile
	}
	
	for _, pair := range certKeyPaths {
		cert, err := tls.LoadX509KeyPair(pair.Cert, pair.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load cert [%s] or key [%s]: %v", pair.Cert, pair.Key, err)
		}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	
	tlsConfig.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		for _, cert := range certs {
			if err := chi.SupportsCertificate(&cert); err == nil {
				return &cert, nil
			}
		}
		return nil, fmt.Errorf("no compatible certificate found for client")
	}


	server.TLSConfig = tlsConfig

	return server, nil
}

