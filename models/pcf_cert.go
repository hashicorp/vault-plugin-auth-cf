package models

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
)

func NewPCFCertificateFromx509(certificate *x509.Certificate) (*PCFCertificate, error) {
	if len(certificate.IPAddresses) != 1 {
		return nil, fmt.Errorf("valid PCF certs have one IP address, but this has %s", certificate.IPAddresses)
	}

	pcfCert := &PCFCertificate{
		InstanceID: certificate.Subject.CommonName,
		IPAddress:  certificate.IPAddresses[0],
	}
	for _, ou := range certificate.Subject.OrganizationalUnit {
		if strings.HasPrefix(ou, "space:") {
			pcfCert.SpaceID = strings.Split(ou, "space:")[1]
			continue
		}
		if strings.HasPrefix(ou, "organization:") {
			pcfCert.OrgID = strings.Split(ou, "organization:")[1]
			continue
		}
		if strings.HasPrefix(ou, "app:") {
			pcfCert.AppID = strings.Split(ou, "app:")[1]
			continue
		}
	}
	if err := pcfCert.validate(); err != nil {
		return nil, err
	}
	return pcfCert, nil
}

func NewPCFCertificate(instanceID, orgID, spaceID, appID, ipAddress string) (*PCFCertificate, error) {
	pcfCert := &PCFCertificate{
		InstanceID: instanceID,
		OrgID:      orgID,
		SpaceID:    spaceID,
		AppID:      appID,
		IPAddress:  net.ParseIP(ipAddress),
	}
	if err := pcfCert.validate(); err != nil {
		return nil, err
	}
	return pcfCert, nil
}

type PCFCertificate struct {
	InstanceID, OrgID, SpaceID, AppID string
	IPAddress                         net.IP
}

func (c *PCFCertificate) validate() error {
	if c.InstanceID == "" {
		return errors.New("no instance ID on given certificate")
	}
	if c.AppID == "" {
		return errors.New("no app ID on given certificate")
	}
	if c.OrgID == "" {
		return errors.New("no org ID on given certificate")
	}
	if c.SpaceID == "" {
		return errors.New("no space ID on given certificate")
	}
	if c.IPAddress.IsUnspecified() {
		return errors.New("ip address is unspecified")
	}
	return nil
}
