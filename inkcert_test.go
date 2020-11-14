package inkcert

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestNewAuthority(t *testing.T) {

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("Works!"))
	})

	httpserver := http.Server{
		TLSConfig: &tls.Config{
			GetCertificate: NewServerDeterministic([]byte{0xDE, 0xAD}, nil).TLSGetCertificate,
		},
		Addr:           "127.0.0.1:4242",
		Handler:        mux,
		MaxHeaderBytes: 1 << 23,
	}

	httpserver.ListenAndServeTLS("", "")
}
