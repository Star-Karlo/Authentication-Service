package config

import "testing"

// Terraform spells the environment "prod"; the older convention was
// "production". Both must switch production safety rules on — the deployed
// stack once matched neither and shipped with Swagger and gRPC reflection
// exposed.
func TestIsProductionAcceptsBothSpellings(t *testing.T) {
	for _, env := range []string{"production", "prod", "PROD", " Production "} {
		if !(&Config{Environment: env}).IsProduction() {
			t.Errorf("IsProduction() = false for %q, want true", env)
		}
	}
	for _, env := range []string{"", "dev", "development", "staging", "prod-like"} {
		if (&Config{Environment: env}).IsProduction() {
			t.Errorf("IsProduction() = true for %q, want false", env)
		}
	}
}
