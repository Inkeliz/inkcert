package inkcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"io"
	"math/big"
	"net"
	"net/url"
	"sync"
	"time"
)

type Info struct {
	Organization  string
	Country       string
	Province      string
	Locality      string
	StreetAddress string
	PostalCode    string
}

type Server struct {
	CAPrivateKey   *ecdsa.PrivateKey
	CADer          []byte
	CA             *x509.Certificate
	ClientRandSeed [32]byte
	Client         map[string]*tls.Certificate
	sync.RWMutex
}

// NewServerDeterministic creates the certificate with an deterministic key,
// it always creates the same certificate/key using the same `seed`.
func NewServerDeterministic(seed []byte, info *Info) *Server {
	seedH := blake2b.Sum512(seed) // hash to avoid seed over 64bytes

	rand, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, seedH[:])
	if err != nil {
		panic(err)
	}

	return NewServer(rand, info)
}

// NewServer creates the certificates using the given rand
func NewServer(rand io.Reader, info *Info) *Server {
	if rand == nil {
		rand = cryptorand.Reader
	}

	if info == nil {
		info = &Info{
			Organization:  "InkCert",
			Country:       "Earth",
			Province:      "Solar",
			Locality:      "Milky Way",
			StreetAddress: "Internet, Earth",
			PostalCode:    "4242",
		}
	}

	server := &Server{Client: make(map[string]*tls.Certificate, 0)}

	server.CA = &x509.Certificate{
		SerialNumber:          newSerial(rand),
		Subject:               newSubject(info),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		return server
	}

	server.CADer, err = x509.CreateCertificate(rand, server.CA, server.CA, sk.Public(), sk)
	if err != nil {
		return server
	}

	server.CAPrivateKey = sk

	rand.Read(server.ClientRandSeed[:])

	return server
}

// It's supposed to be used inside the `TLSConfig` as such:
//  CERTSERVER := inkcert.NewServer(nil, nil)
//  http.Server{
// 	   TLSConfig: &tls.Config{
//			GetCertificate: CERTSERVER.TLSGetCertificate,
//	   }
func (s *Server) TLSGetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Doesn't support SNI or it's an IP
	if info.ServerName == "" {
		ip := info.Conn.RemoteAddr().(*net.TCPAddr)

		s.RLock()
		certs, ok := s.Client[ip.IP.String()]
		s.RUnlock()
		if ok {
			return certs, nil
		}

		t, err := s.CreateClientCertIP(ip.IP)
		return t, err
	}

	s.RLock()
	certs, ok := s.Client[info.ServerName]
	s.RUnlock()
	if ok {
		return certs, nil
	}

	u, _ := url.Parse(info.ServerName)
	return s.CreateClientCertDomain(u)
}

func (s *Server) sign(rand io.Reader, domain fmt.Stringer, x *x509.Certificate) (*tls.Certificate, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		return nil, err
	}

	certDer, err := x509.CreateCertificate(rand, x, s.CA, sk.Public(), s.CAPrivateKey)
	if err != nil {
		return nil, err
	}

	caPem := new(bytes.Buffer)
	pem.Encode(caPem, &pem.Block{Type: "CERTIFICATE", Bytes: s.CADer})

	certPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certDer})

	skx, _ := x509.MarshalPKCS8PrivateKey(sk)
	skPem := new(bytes.Buffer)
	pem.Encode(skPem, &pem.Block{Type: "EC PRIVATE KEY", Bytes: skx})

	tlscert, err := tls.X509KeyPair(append(certPem.Bytes(), caPem.Bytes()...), skPem.Bytes())
	if err != nil {
		return nil, err
	}

	s.Lock()
	s.Client[domain.String()] = &tlscert
	s.Unlock()

	return &tlscert, nil
}

func (s *Server) CreateClientCertDomain(u *url.URL) (*tls.Certificate, error) {
	rand := s.createGenerator(u)

	cert := s.createClient(rand, &Info{
		Organization:  u.String(),
		Country:       "Internet",
		Province:      "Internet",
		Locality:      "Internet",
		StreetAddress: "Internet",
		PostalCode:    "4242",
	})
	cert.URIs = []*url.URL{u}

	return s.sign(rand, u, cert)
}

func (s *Server) CreateClientCertIP(ip net.IP) (*tls.Certificate, error) {
	rand := s.createGenerator(ip)

	cert := s.createClient(rand, &Info{
		Organization:  ip.String(),
		Country:       "Internet",
		Province:      "Internet",
		Locality:      "Internet",
		StreetAddress: "Internet",
		PostalCode:    "00000",
	})
	cert.IPAddresses = []net.IP{ip}

	return s.sign(rand, ip, cert)
}

func (s *Server) createGenerator(data fmt.Stringer) io.Reader {
	h, _ := blake2b.New(32, s.ClientRandSeed[:])
	h.Write([]byte(data.String()))

	r, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, h.Sum(nil))
	return r
}

func (s *Server) createClient(rand io.Reader, info *Info) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: newSerial(rand),
		Subject:      newSubject(info),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

func newSerial(rand io.Reader) *big.Int {
	r := make([]byte, 16)
	rand.Read(r)

	return big.NewInt(0).SetBytes(r)
}

func newSubject(info *Info) pkix.Name {
	if info == nil {
		info = new(Info)
	}

	return pkix.Name{
		Organization:  []string{info.Organization},
		Country:       []string{info.Country},
		Province:      []string{info.Province},
		Locality:      []string{info.Locality},
		StreetAddress: []string{info.StreetAddress},
		PostalCode:    []string{info.PostalCode},
	}
}
