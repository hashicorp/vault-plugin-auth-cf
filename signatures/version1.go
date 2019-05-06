package signatures

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/pkg/errors"
)

const TimeFormat = "2006-01-02T15:04:05Z"

func Sign(logger hclog.Logger, pathToPrivateKey, bodyJson string) (signature string, signingTime time.Time, err error) {
	logger.Debug("building signature")

	// Make sure we can retrieve and read in the RSA private key.
	keyBytes, err := ioutil.ReadFile(pathToPrivateKey)
	if err != nil {
		return "", time.Time{}, err
	}
	block, _ := pem.Decode(keyBytes)
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", time.Time{}, err
	}

	signingTime = time.Now().UTC()
	toSign, err := generateStringToSign(logger, bodyJson, signingTime.Format(TimeFormat))
	if err != nil {
		return "", time.Time{}, err
	}
	hashed := generateHash(toSign)

	sig, err := rsa.SignPSS(rand.Reader, rsaPrivateKey, crypto.SHA256, hashed, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	signature = base64.URLEncoding.EncodeToString(sig)
	logger.Debug(fmt.Sprintf("final signature: %s", signature))
	return signature, signingTime, nil
}

// Note - we will need to pass the signing time as a header like the Date header
func Verify(logger hclog.Logger, pathToClientCert, signature, bodyJson, signingTime string) error {
	logger.Debug("verifying signature")

	// Make sure we can retrieve and read in the client certificate.
	rest, err := ioutil.ReadFile(pathToClientCert)
	if err != nil {
		return err
	}

	// Reconstruct the string that should have been signed.
	toSign, err := generateStringToSign(logger, bodyJson, signingTime)
	if err != nil {
		return err
	}
	hashed := generateHash(toSign)

	// Use the CA certificate to verify the signature we've received.
	sig, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	var lastErr error
	var block *pem.Block
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		clientCerts, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			lastErr = err
			continue
		}
		for _, clientCert := range clientCerts {
			publicKey, ok := clientCert.PublicKey.(*rsa.PublicKey)
			if !ok {
				lastErr = fmt.Errorf("not an rsa public key, it's a %t", clientCert.PublicKey)
				continue
			}

			if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hashed, sig, nil); err != nil {
				lastErr = err
				continue
			}
			// Success
			return nil
		}
	}
	return lastErr
}

func IsIssuer(pathToCACert, pathToClientCert string) (bool, error) {

	caCertBytes, err := ioutil.ReadFile(pathToCACert)
	if err != nil {
		return false, err
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caCertBytes); !ok {
		return false, errors.New("couldn't append CA certificates")
	}

	rest, err := ioutil.ReadFile(pathToClientCert)
	if err != nil {
		return false, err
	}

	verifyOpts := x509.VerifyOptions{
		Roots: pool,
	}

	var block *pem.Block
	var lastErr error
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		clientCerts, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			lastErr = err
			continue
		}
		for _, clientCert := range clientCerts {
			if _, err := clientCert.Verify(verifyOpts); err != nil {
				lastErr = err
				continue
			}
			// Success
			return true, nil
		}
	}
	return false, lastErr
}

func generateStringToSign(logger hclog.Logger, bodyJson, signingTime string) (string, error) {
	logger.Debug(fmt.Sprintf("preparing body for signature: %s", bodyJson))
	logger.Debug(fmt.Sprintf("using signing time: %s", signingTime))

	bodyBytes, err := json.Marshal(bodyJson)
	if err != nil {
		return "", err
	}

	logger.Debug(fmt.Sprintf("escaped body json to: %s", bodyBytes))

	hasher := sha256.New()
	hasher.Write(bodyBytes)
	bodySha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	logger.Debug(fmt.Sprintf("created body sha: %s", bodySha))

	toSign := "time=" + signingTime + "&body=" + fmt.Sprintf("%s", bodySha)

	logger.Debug(fmt.Sprintf("generated string to sign: %s", toSign))
	return toSign, nil
}

func generateHash(s string) []byte {
	hashed := sha256.Sum256([]byte(s))
	return hashed[:]
}