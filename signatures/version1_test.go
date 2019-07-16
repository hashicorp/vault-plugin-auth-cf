package signatures

import (
	"fmt"
	"github.com/hashicorp/vault-plugin-auth-pcf/util"
	"io/ioutil"
	"testing"
	"time"

	"github.com/hashicorp/vault-plugin-auth-pcf/testing/certificates"
)

func TestWithLance(t *testing.T) {
	tm, err := time.Parse(TimeFormat, "2019-07-15T22:06:58Z")
	if err != nil {
		t.Fatal(err)
	}
	sigData := &SignatureData{
		SigningTime:            tm,
		Role:                   "spring",
		CFInstanceCertContents: `-----BEGIN CERTIFICATE-----
MIIEmTCCAwGgAwIBAgIRAK0auU1vLEtWXl4C4ejjQAUwDQYJKoZIhvcNAQELBQAw
QzEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MRswGQYDVQQD
ExJpbnN0YW5jZUlkZW50aXR5Q0EwHhcNMTkwNzE1MDExMjE3WhcNMTkwNzE2MDEx
MjE3WjCByDGBnjA4BgNVBAsTMW9yZ2FuaXphdGlvbjo0MGRjYWQ1My01OGEyLTQ0
MzAtYmI3MS1mMTczMmQ1OWQ2YTEwMQYDVQQLEypzcGFjZTo5ZDY3ZDc0MC0wMmFj
LTQ0MzYtOTVlOS1jZDQ0ODU2NGM1N2UwLwYDVQQLEyhhcHA6ZjBkZTg1NGQtZjIz
Yy00MjE5LTk3YzgtYzBhOGQ5ODFjMTY4MSUwIwYDVQQDExw2OGNkMmY2YS0xYTk0
LTRmNGYtNjBmOC04NGEzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
q0NlC4JV8RYJUZSSskUMcCg/mENa+QnUWztBpMSZwQhJxN4ETOphTPGDhZ2M51ck
lnjm0Tf7zQJHB1qlvF9CKBn82gCxm2rt16f9D3veCkSyeJYdBDzWk30AjDp1o0lb
CPc0Fyv3BI8pbKnebhGkUIREnU9SONCqAYCI/owes+mkqKfSM9OhI7xHV7t7H18q
Ff1wmHqHWjOqmsJGf2SKV//dSsTvGJbfesa3mlqPlms6oElXKpshGeGn+Jieun/U
JU5qPqG8t65KZVWjOWUFoMTbb7Zh0zfNNhB7njqv9fTmhCbuiFu+sRHbnYXAqBaB
J/4PREYnPuPCkA3E9u3+hQIDAQABo4GBMH8wDgYDVR0PAQH/BAQDAgOoMB0GA1Ud
JQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAfBgNVHSMEGDAWgBScfHJyfGbRBpTb
R8et8zpsrDlMJzAtBgNVHREEJjAkghw2OGNkMmY2YS0xYTk0LTRmNGYtNjBmOC04
NGEzhwQK//gEMA0GCSqGSIb3DQEBCwUAA4IBgQAFYtEiofwM7WhFnB/dqcoEjswd
IvCMzJv+zUL634YPXaa+aPBrtAuMJNLaLg7E0roLlWs7fwNP1/urgvFuQWu2EfUe
C5CptauvRS+4O3z/fQwkuwxP1O0nhKpe6jvGTGG1NxLYqXEKNMApzeRqmyn7G599
i1Vhr1Fq617rWYOxGxhK9OR7z3LMncMalbBCEJEvRihQeFH5PVsf8DN6jQHkDRma
6L9SRohBRllr0zJ8nfaIpTs3Ky/fXZPrPDNVcSYPH+afsoL8JHUAlcfWaMmFicBi
B3YA2PCn/HIkxodWW07ITT3yFwhZ3jOdXYPn6CDo3xisE5T8wRckVg/GC06wEhFY
tDuD6lV8Oa4eLRVidvrwKvmylqyC/3G1naOZf/L3LafihDIpCXqm+k42Fg3zCozh
67jvF4dDersw7iTO9LBCmaco6gchceSce0/Xwmrgucps8lKTmtfDNAlom1/O01tH
g+c2XnYE8Cyj5TDHqSRInq8xB0nX0OsB7PDOxvs=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEajCCAtKgAwIBAgIQZbZgkdNQIVnt+RQ61Szc7DANBgkqhkiG9w0BAQsFADA6
MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoTDUNsb3VkIEZvdW5kcnkxEjAQBgNVBAMT
CWFwcFJvb3RDQTAeFw0xOTA1MTAxOTI1MDlaFw0yMDA1MDkxOTI1MDlaMEMxDDAK
BgNVBAYTA1VTQTEWMBQGA1UEChMNQ2xvdWQgRm91bmRyeTEbMBkGA1UEAxMSaW5z
dGFuY2VJZGVudGl0eUNBMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA
z0B64IrFFMjVhO1YOSm72DQJghPbPrfE4mcd9CWqY0C2BxBOslEUB7jsQO+z0zYF
WDGbQsYrHFOY+bTp+ZX5P1g9742IlUrC3JImz2Rr5MEnXaWbfaz4OHBi9esLqoeK
epzgSNgItUJlv6Nc9CGMicLjJGVk9f9GFc4YBB1CYBEFst4mKXPTjFS/BzFLUsBI
IAJOZ3HdSKq2VCV98S56LMGE/F822Au13rIXAgp223WFLzcJAdIxhnM0AmXjzOC1
59oY+8lXOWZYPy9BJUe4WHnFK1f7J6t5+8y6tw0+NrSgs1NR2A9WJKodde/+OFQf
eZElx9lCabmHpdpwt+Z6u0U59k2EGEJnaGIlem+30rb778ek20pA7qR7kUYSvfBP
7/ZTgNbGmYICjTkLpGIJJZo/4MxNXpfDaoHYibaaRrB6kiRaOO1+iv0yrwBBdmoc
naW0Rez8T49WREa+du9X7WIOs0JxSEp78LGYlHj3p33ocRQGe9cyJVDJYzTVWme7
AgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBScfHJyfGbRBpTbR8et8zpsrDlMJzAfBgNVHSMEGDAWgBRxcDY/BBorhmYx
Nz+WE4FxnWxgGjANBgkqhkiG9w0BAQsFAAOCAYEArH8vJdIPPncA7Cq+K2mZHI3j
Yv2GqyZAW3RO0V3udcunRCKZs92IjOTSelkuLZXS7at247RcmFMyAEX3JU+rqPwx
vXAbrAB2lP0ssuCsnq7fjzrjtYOKTFNI8dRrHIm36Y1T9iQCvenlHAin7vS//JMt
WaPAQPH0XqkS9WiyIbqNj0hkuDOej0o+K+VecxyIgtuI7f/wIMJl3JUOb40mSFn7
X8kGBaxYutD9uf9Gs4hPcESdtjjaBX0dS8c1vlCZmNKNOj18bb2hCZ+29Q3lHrK6
a7iJoqxMh9Edvi8M4xCpgJgNPCf74FFxlShARIQXqy/GifPw6uxlmKCT0nBb/xV9
pwYF4Uem9E1a3EVugsTpheNYUuVxSdEJgmg8hX3Bchn7hdeDo6uCUzk79yWurTSH
UafnQWajYixE1s+9g3vuLnnkQLpvHc8iKGIniXd5WW8DKbQcs8qGgrDuD5LcCysN
kKiNuFipTc6ysQj3DL+FeW5lhN3xYkXwm37eBS0J
-----END CERTIFICATE-----`,
	}
	fmt.Println(sigData.toSign())
	fmt.Printf("%x\n", sigData.hash())
}

func TestSignVerifyIssuedByFakes(t *testing.T) {
	testCerts, err := certificates.Generate("doesn't", "really", "matter", "here", "10.255.181.105")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := testCerts.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	signatureData := &SignatureData{
		SigningTime:            time.Now(),
		Role:                   "my-role",
		CFInstanceCertContents: testCerts.InstanceCertificate,
	}

	signature, err := Sign(testCerts.PathToInstanceKey, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	signingCert, err := Verify(signature, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	intermediateCert, identityCert, err := util.ExtractCertificates(testCerts.InstanceCertificate)
	if err != nil {
		t.Fatal(err)
	}

	if err := util.Validate([]string{testCerts.CACertificate}, intermediateCert, identityCert, signingCert); err != nil {
		t.Fatal(err)
	}
}

func TestSignVerifyIssuedByReal(t *testing.T) {
	certBytes, err := ioutil.ReadFile("../testdata/real-certificates/instance.crt")
	if err != nil {
		t.Fatal(err)
	}
	signatureData := &SignatureData{
		SigningTime:            time.Now(),
		Role:                   "my-role",
		CFInstanceCertContents: string(certBytes),
	}

	signature, err := Sign("../testdata/real-certificates/instance.key", signatureData)
	if err != nil {
		t.Fatal(err)
	}

	signingCert, err := Verify(signature, signatureData)
	if err != nil {
		t.Fatal(err)
	}

	caCertBytes, err := ioutil.ReadFile("../testdata/real-certificates/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, identityCert, err := util.ExtractCertificates(string(certBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := util.Validate([]string{string(caCertBytes)}, intermediateCert, identityCert, signingCert); err == nil {
		t.Fatal(`expected error: x509: certificate has expired or is not yet valid`)
	}
}

// TestSignature is present to help implement the signing algorithm in other languages.
func TestSignature(t *testing.T) {
	sampleSigningTime := "2019-05-20T22:08:40Z"
	sampleRole := "sample-role"
	sampleCertificate := "../testdata/real-certificates/instance.crt"
	sampleKey := "../testdata/real-certificates/instance.key"

	signingTime, err := time.Parse(TimeFormat, sampleSigningTime)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := ioutil.ReadFile(sampleCertificate)
	if err != nil {
		t.Fatal(err)
	}
	signatureData := &SignatureData{
		SigningTime:            signingTime,
		Role:                   sampleRole,
		CFInstanceCertContents: string(certBytes),
	}
	fmt.Println(`hashing string: "` + signatureData.toSign() + `"`)
	signature, err := Sign(sampleKey, signatureData)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sha256sum is: %x\n", signatureData.hash())
	fmt.Println(`resulting signature: "` + signature + `"`)
	fmt.Println(`resulting signatures will vary on each run due to random bytes included in the signature`)
}
