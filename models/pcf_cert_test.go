package models

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

/*
This is what we expect to see from the testdata/real-certificates/instance.crt,
which was pulled directly from the CF Dev environment.

$ openssl x509 -in instance.crt -text -noout
CFInstanceCertContents:
    Data:
        Version: 3 (0x2)
        Serial Number:
            94:7e:54:94:3e:51:46:36:77:2f:b3:f8:10:13:4e:1e
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=USA, O=Cloud Foundry, CN=instanceIdentityCA
        Validity
            Not Before: Apr 27 04:30:00 2019 GMT
            Not After : Apr 28 04:30:00 2019 GMT
        Subject: OU=organization:34a878d0-c2f9-4521-ba73-a9f664e82c7b, OU=space:3d2eba6b-ef19-44d5-91dd-1975b0db5cc9, OU=app:2d3e834a-3a25-4591-974c-fa5626d5d0a1, CN=f9c7cd7d-1612-4f57-63a8-f995
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:dc:d4:be:35:fb:03:b5:93:f3:8f:01:c5:84:ed:
                    54:37:fd:56:bc:0c:b8:64:71:bb:d6:44:eb:1c:27:
                    58:c7:ee:40:49:08:ca:f5:da:0f:4c:8f:8f:c5:72:
                    fc:2b:e9:26:54:85:1c:40:e8:5d:33:89:ed:4f:93:
                    7b:d0:b2:7d:a6:c2:01:9e:37:d7:d1:ff:e1:1a:34:
                    b6:53:b6:9a:56:32:b0:4c:8e:fe:02:27:f4:c5:4e:
                    4e:25:0f:63:8c:73:51:78:98:fd:60:bc:fe:a3:a3:
                    b4:0d:f3:2f:1d:8e:20:45:19:5a:dd:b8:2c:ea:14:
                    64:ce:3e:b0:54:61:18:ce:46:10:92:e7:7b:97:aa:
                    49:69:7d:8e:0a:25:33:d9:c5:9b:87:60:f6:e8:6e:
                    6e:b3:01:3e:3e:73:27:a6:79:55:cc:2b:7c:77:71:
                    34:d7:03:0f:8b:69:f6:70:f2:94:6b:d3:a7:80:52:
                    40:93:1b:17:d2:90:4a:3d:7f:b8:bb:05:4a:57:8d:
                    4b:95:34:7c:15:e9:87:27:ec:e6:f5:48:c0:4b:34:
                    5c:dd:1e:fb:e7:dd:fc:56:fc:d7:22:f3:90:bf:44:
                    16:59:c5:db:5b:c0:2a:87:7d:6e:a3:a7:51:75:8a:
                    57:6c:57:85:81:7e:9e:ef:f6:48:dd:31:22:fb:b3:
                    27:4b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment, Key Agreement
            X509v3 Extended Key Usage:
                TLS Web Client Authentication, TLS Web Server Authentication
            X509v3 Authority Key Identifier:
                keyid:BB:DF:3C:6A:93:84:D2:F5:6C:6E:5A:0A:87:CA:E2:2B:2A:03:C4:51

            X509v3 Subject Alternative Name:
                DNS:f9c7cd7d-1612-4f57-63a8-f995, IP Address:10.255.181.105
    Signature Algorithm: sha256WithRSAEncryption
         43:01:5e:84:e0:c2:13:d8:89:4d:48:66:a1:b1:2e:e1:87:6b:
         70:af:25:cf:47:48:17:71:ae:3f:68:d7:7f:83:23:ea:a5:bf:
         78:62:1f:ff:b6:eb:d5:d3:12:83:2e:2d:36:aa:9d:01:45:b7:
         a5:8a:02:bb:2f:bb:a4:cd:fc:b7:09:cf:a1:00:70:28:c5:5e:
         eb:c3:64:86:ea:c4:8b:a1:f8:c7:ad:2c:29:70:02:8d:41:93:
         5e:dc:6d:1f:b8:a4:8a:b1:42:c5:04:39:37:36:85:95:80:bc:
         42:37:d7:ec:ed:49:5f:e1:92:c2:60:01:96:81:78:65:6e:fb:
         4c:c2:d5:06:82:4c:50:ec:7d:a3:f6:ca:52:fa:af:39:49:24:
         47:a3:1e:6a:55:53:e0:b9:ea:4c:3f:85:28:8d:56:d2:49:a8:
         e1:c8:f1:79:51:2a:e1:72:3f:e2:54:fb:58:69:41:21:37:de:
         02:97:4d:1a:8a:a4:a3:a0:0a:79:28:16:4e:3c:86:e2:3a:52:
         f1:89:e4:f9:93:ce:24:d6:04:09:1c:51:75:11:27:a7:d0:b5:
         74:cb:ac:2f:bf:2a:0f:f8:7f:f9:fe:f5:dd:ba:45:4b:a3:ed:
         3e:aa:bb:55:f7:fa:f7:af:ef:d4:73:47:59:b8:b9:e6:21:24:
         56:7e:c2:6f:29:f6:de:86:f3:9a:5d:ab:65:cb:0c:85:93:81:
         4d:5c:00:2d:f3:fd:10:ee:09:53:18:07:3e:01:0d:ca:c6:d7:
         ee:29:a7:8e:cb:d5:14:09:74:21:c0:48:2b:96:75:fb:90:08:
         09:b4:cb:a1:8e:a2:42:fc:f2:2b:ad:65:14:ad:bb:e0:74:95:
         28:d1:38:d5:a3:8b:bb:d7:c6:82:a5:03:28:99:73:cd:be:9a:
         99:ae:96:35:dd:11:49:77:bd:d0:d7:c1:6b:35:95:0b:b8:e9:
         4c:bd:37:5f:0e:c2:49:c0:65:b0:e5:24:d1:9a:1d:c8:c9:24:
         f3:50:6e:e5:7b:ae

*/

func TestNewPcfCertificateFromx509(t *testing.T) {
	certBytes, err := ioutil.ReadFile("../testdata/real-certificates/instance.crt")
	if err != nil {
		t.Fatal(err)
	}
	var certs []*x509.Certificate
	var block *pem.Block
	for {
		block, certBytes = pem.Decode(certBytes)
		if block == nil {
			break
		}
		clientCerts, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		for _, clientCert := range clientCerts {
			certs = append(certs, clientCert)
		}
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs but received %d", len(certs))
	}
	pcfCert, err := NewPCFCertificateFromx509(certs[1])
	if err == nil {
		t.Fatal("expected the second certificate to fail verification")
	}
	pcfCert, err = NewPCFCertificateFromx509(certs[0])
	if err != nil {
		t.Fatal("expected the first certificate to be valid")
	}
	if pcfCert.InstanceID != "f9c7cd7d-1612-4f57-63a8-f995" {
		t.Fatalf("expected %s but received %s", "f9c7cd7d-1612-4f57-63a8-f995", pcfCert.InstanceID)
	}
	if pcfCert.AppID != "2d3e834a-3a25-4591-974c-fa5626d5d0a1" {
		t.Fatalf("expected %s but received %s", "2d3e834a-3a25-4591-974c-fa5626d5d0a1", pcfCert.AppID)
	}
	if pcfCert.SpaceID != "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9" {
		t.Fatalf("expected %s but received %s", "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9", pcfCert.SpaceID)
	}
	if pcfCert.OrgID != "34a878d0-c2f9-4521-ba73-a9f664e82c7b" {
		t.Fatalf("expected %s but received %s", "34a878d0-c2f9-4521-ba73-a9f664e82c7b", pcfCert.OrgID)
	}
	if pcfCert.IPAddress.String() != "10.255.181.105" {
		t.Fatalf("expected %s but received %s", "10.255.181.105", pcfCert.IPAddress.String())
	}
}

func TestNewPCFCertificate(t *testing.T) {
	pcfCert, err := NewPCFCertificate("f9c7cd7d-1612-4f57-63a8-f995", "34a878d0-c2f9-4521-ba73-a9f664e82c7b", "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9", "2d3e834a-3a25-4591-974c-fa5626d5d0a1", "10.255.181.105")
	if err != nil {
		t.Fatal(err)
	}
	if pcfCert.InstanceID != "f9c7cd7d-1612-4f57-63a8-f995" {
		t.Fatalf("expected %s but received %s", "f9c7cd7d-1612-4f57-63a8-f995", pcfCert.InstanceID)
	}
	if pcfCert.AppID != "2d3e834a-3a25-4591-974c-fa5626d5d0a1" {
		t.Fatalf("expected %s but received %s", "2d3e834a-3a25-4591-974c-fa5626d5d0a1", pcfCert.AppID)
	}
	if pcfCert.SpaceID != "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9" {
		t.Fatalf("expected %s but received %s", "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9", pcfCert.SpaceID)
	}
	if pcfCert.OrgID != "34a878d0-c2f9-4521-ba73-a9f664e82c7b" {
		t.Fatalf("expected %s but received %s", "34a878d0-c2f9-4521-ba73-a9f664e82c7b", pcfCert.OrgID)
	}
	if pcfCert.IPAddress.String() != "10.255.181.105" {
		t.Fatalf("expected %s but received %s", "10.255.181.105", pcfCert.IPAddress.String())
	}
}
