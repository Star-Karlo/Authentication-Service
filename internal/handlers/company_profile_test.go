package handlers

import (
	"testing"
)

func TestProfileRequestMapsTheProfileScreenFields(t *testing.T) {
	npwp := " 01.234.567.8-901.000 "
	desc := "Angkutan darat"
	logo := "data:image/png;base64,AAAA"
	bank := map[string]interface{}{"bankName": "BANK BRI", "accountNumber": "123"}
	profile := map[string]interface{}{"foundedYear": "2020", "nib": "1234567890123"}
	r := profileRequest{NPWP: &npwp, CompanyProfile: &desc, LogoURL: &logo, BankAccount: &bank, Profile: &profile}

	fields, err := r.fields()
	if err != nil {
		t.Fatal(err)
	}
	if fields["npwp"] != "01.234.567.8-901.000" {
		t.Fatalf("npwp not trimmed: %v", fields["npwp"])
	}
	if fields["company_profile"] != desc || fields["logo_url"] != logo {
		t.Fatalf("description/logo not mapped: %v", fields)
	}
	if _, ok := fields["bank_account"]; !ok {
		t.Fatal("bank_account missing")
	}
	if _, ok := fields["profile"]; !ok {
		t.Fatal("profile missing")
	}

	// Fields the caller did not send stay untouched.
	blank := profileRequest{}
	fields, _ = blank.fields()
	if len(fields) != 0 {
		t.Fatalf("empty request must change nothing, got %v", fields)
	}
}
