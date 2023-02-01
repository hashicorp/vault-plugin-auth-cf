// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package util

import (
	"io/ioutil"
	"testing"
)

func TestExtractCertificates(t *testing.T) {
	sampleCertBytes, err := ioutil.ReadFile("../testdata/real-certificates/instance.crt")
	if err != nil {
		t.Fatal(err)
	}
	intermediate, identity, err := ExtractCertificates(string(sampleCertBytes))
	if err != nil {
		t.Fatal(err)
	}
	expected := "CN=instanceIdentityCA,O=Cloud Foundry,C=USA"
	if intermediate.Subject.String() != expected {
		t.Fatalf("expected %q but received %q", expected, intermediate.Subject.String())
	}
	expected = "CN=f9c7cd7d-1612-4f57-63a8-f995,OU=organization:34a878d0-c2f9-4521-ba73-a9f664e82c7b+OU=space:3d2eba6b-ef19-44d5-91dd-1975b0db5cc9+OU=app:2d3e834a-3a25-4591-974c-fa5626d5d0a1"
	if identity.Subject.String() != expected {
		t.Fatalf("expected %q but received %q", expected, identity.Subject.String())
	}
}
