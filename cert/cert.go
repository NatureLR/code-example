package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"
)

func GenCA() (string, string, error) {
	// 生成一个 CA 证书和私钥
	// 生成 ECDSA 私钥
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate CA private key: %v", err)
	}
	// 创建 CA 证书模板
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "app",               // CN
			Country:            []string{"CN"},      // C
			Organization:       []string{"k8s"},     // O
			OrganizationalUnit: []string{"System"},  // Ou
			Locality:           []string{"BeiJing"}, // L
			Province:           []string{"BeiJing"}, // ST
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(50 * 365 * 24 * time.Hour), // CA 有效期 50 年
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	// 自签名 CA 证书
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create CA certificate: %v", err)
	}

	// 返回 CA 证书和私钥
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	return string(certPEM), string(keyPEM), nil
}

// GenCert uses an existing CA to generate a new certificate and private key.
func GenCert(caCertPEM, caKeyPEM string, newCertTemplate *x509.Certificate) (string, string, error) {
	// Parse CA certificate
	caCertBlock, _ := pem.Decode([]byte(caCertPEM))
	if caCertBlock == nil {
		return "", "", fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	// Parse CA private key
	caKeyBlock, _ := pem.Decode([]byte(caKeyPEM))
	if caKeyBlock == nil {
		return "", "", fmt.Errorf("failed to decode CA private key PEM")
	}

	var caKey interface{}
	if caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes); err != nil {
		if caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes); err != nil {
			if caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes); err != nil {
				return "", "", fmt.Errorf("failed to parse CA private key: %v", err)
			}
		}
	}

	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // Or use ECDSA
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	// Sign the new certificate with the CA's private key
	certBytes, err := x509.CreateCertificate(rand.Reader, newCertTemplate, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the new certificate as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	// Encode the new private key as PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return string(certPEM), string(keyPEM), nil
}

// GenCnVpciCert 生成cnivpc的证书
func GenTestCert(caCert, caKey string) (string, string, error) {
	newCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), // Unique serial number
		Subject: pkix.Name{
			CommonName:         "app",               // CN
			Country:            []string{"CN"},      // C
			Organization:       []string{"k8s"},     // O
			OrganizationalUnit: []string{"System"},  // Ou
			Locality:           []string{"BeiJing"}, // L
			Province:           []string{"BeiJing"}, // ST
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(50 * 365 * 24 * time.Hour), // 证书有效期50年
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			"xxxxx.kube-system.svc",
		},
	}
	return GenCert(caCert, caKey, newCertTemplate)
}

func GenAllCert() {
	ca, caKey, err := GenCA()
	if err != nil {
		log.Fatalln(err)
	}
	cert, key, err := GenTestCert(ca, caKey)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(ca, cert, key)
}
