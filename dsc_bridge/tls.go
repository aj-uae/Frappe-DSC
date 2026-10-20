package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"runtime"
	"time"
)

// macOS (10.15+) rejects TLS server certificates valid for more than 825 days, even
// when the user has trusted them, so Safari and Chrome on a Mac refuse a 10-year cert.
const darwinMaxCertDays = 820

func certLifetime() time.Duration {
	if runtime.GOOS == "darwin" {
		return darwinMaxCertDays * 24 * time.Hour
	}
	return 10 * 365 * 24 * time.Hour
}

// certUsable reports whether an existing cert can be kept: on macOS it must fit the
// 825-day limit and not be close to expiry.
func certUsable(cert tls.Certificate) bool {
	if runtime.GOOS != "darwin" {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > 825*24*time.Hour {
		return false
	}
	return time.Until(leaf.NotAfter) > 30*24*time.Hour
}

// EnsureTLSCert loads or generates the agent's self-signed TLS certificate.
// Returns the tls.Certificate and the SHA-256 fingerprint of the cert DER.
func EnsureTLSCert(cfg *Config) (tls.Certificate, string, error) {
	// Try loading existing cert
	if fileExists(cfg.TLSCertPath) && fileExists(cfg.TLSKeyPath) {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err == nil && certUsable(cert) {
			fp := certFingerprint(cert.Certificate[0])
			return cert, fp, nil
		}
		// If loading fails or the cert is no longer acceptable, regenerate
	}

	// Generate new self-signed certificate
	cert, err := generateSelfSignedCert(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generating TLS cert: %w", err)
	}

	fp := certFingerprint(cert.Certificate[0])
	return cert, fp, nil
}

func generateSelfSignedCert(certPath, keyPath string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "dsc-bridge",
			Organization: []string{"DSC Bridge Agent"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(certLifetime()),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Write cert PEM
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write key PEM
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.LoadX509KeyPair(certPath, keyPath)
}

// certFingerprint returns the SHA-256 hex fingerprint of a DER-encoded certificate.
func certFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
