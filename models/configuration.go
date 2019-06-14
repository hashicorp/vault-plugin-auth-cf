package models

// Configuration is the config as it's reflected in Vault's storage system.
type Configuration struct {
	// IdentityCACertificates are the CA certificates that should be used for verifying client certificates.
	IdentityCACertificates []string `json:"identity_ca_certificates"`

	// IdentityCACertificates that, if presented by the PCF API, should be trusted.
	PCFAPICertificates []string `json:"pcf_api_trusted_certificates"`

	// PCFAPIAddr is the address of PCF's API, ex: "https://api.dev.cfdev.sh" or "http://127.0.0.1:33671"
	PCFAPIAddr string `json:"pcf_api_addr"`

	// The username for the PCF API.
	PCFUsername string `json:"pcf_username"`

	// The password for the PCF API.
	PCFPassword string `json:"pcf_password"`

	// The maximum minutes old a login request's signing time can be.
	// This is configurable because in some test environments we found as much as 2 hours of clock drift.
	LoginMaxMinOld int `json:"login_max_minutes_old"`

	// The maximum minutes ahead a login request's signing time can be.
	// This is configurable because in some test environments we found as much as 2 hours of clock drift.
	LoginMaxMinAhead int `json:"login_max_minutes_ahead"`
}
