package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	default:
		return nil
	}
}

func Generate(instanceID, orgID, spaceID, appID, ipAddress string) (caCert, instanceCert, instanceKey string, err error) {

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", "", err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Organization: []string{"Testing, Inc."},
			CommonName:   "test-CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(caPrivateKey), caPrivateKey)
	if err != nil {
		return "", "", "", err
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	caCert = out.String()
	out.Reset()

	block, certBytes := pem.Decode([]byte(caCert))
	if block == nil {
		return "", "", "", errors.New("block shouldn't be nil")
	}
	if len(certBytes) > 0 {
		return "", "", "", errors.New("there shouldn't be more bytes")
	}
	ca509cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", "", err
	}

	template = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Organization: []string{"Cloud Foundry"},
			OrganizationalUnit: []string{
				fmt.Sprintf("organization:%s", orgID),
				fmt.Sprintf("space:%s", spaceID),
				fmt.Sprintf("app:%s", appID),
			},
			CommonName: instanceID,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           []net.IP{net.ParseIP(ipAddress)},
	}

	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &template, ca509cert, publicKey(clientPrivateKey), caPrivateKey)
	if err != nil {
		return "", "", "", err
	}

	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	instanceCert = out.String()
	out.Reset()

	pem.Encode(out, pemBlockForKey(clientPrivateKey))
	instanceKey = out.String()
	out.Reset()

	return caCert, instanceCert, instanceKey, nil
}
