package classify

import "testing"

func TestValidatorsCommon(t *testing.T) {
	tests := []struct {
		name  string
		fn    func(string) bool
		valid string
		bad   string
	}{
		{"email", ValidEmail, "jane.doe@example.com", "not-an-email"},
		{"phone", ValidPhone, "+7 (999) 123-45-67", "111"},
		{"ip", ValidIP, "2001:db8::1", "999.1.1.1"},
		{"credit_card", ValidCreditCard, "4111 1111 1111 1111", "4111 1111 1111 1112"},
		{"dob", ValidDOB, "1990-01-02", "1800-01-02"},
		{"latitude", ValidLatitude, "55.7558", "155.1"},
		{"longitude", ValidLongitude, "37.6173", "237.1"},
		{"entropy", ValidEntropy, "demoTokenValueABC123xyz789secret", "550e8400-e29b-41d4-a716-446655440000"},
		{"password_hash", ValidPasswordHash, "$2a$12$abcdefghijklmnopqrstuu2T9u9b63Y5mLL8vD2RyJ9A2H9L6S8W6", "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.fn(tt.valid) {
				t.Fatalf("expected valid value")
			}
			if tt.fn(tt.bad) {
				t.Fatalf("expected invalid value")
			}
		})
	}
}

func TestAddressValidatorAvoidsLooseFalsePositives(t *testing.T) {
	if !ValidAddress("123 Main Street") {
		t.Fatal("expected street address")
	}
	if !ValidAddress("ул. Ленина д. 10") {
		t.Fatal("expected Russian street address")
	}
	for _, value := range []string{"12345 best street food place", "the average is 150", "street food 123"} {
		if ValidAddress(value) {
			t.Fatalf("expected false positive control to fail: %q", value)
		}
	}
}

func TestPasswordHashDoesNotMatchArbitraryHex(t *testing.T) {
	rawHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if ValidPasswordHash(rawHex) {
		t.Fatal("arbitrary raw hex should not be classified as a password hash by value alone")
	}
	if !ValidPasswordHash("sha256:" + rawHex) {
		t.Fatal("expected prefixed sha256 hash")
	}
}

func TestDOBRejectsFutureDate(t *testing.T) {
	if ValidDOB("2999-01-01") {
		t.Fatal("future date must not be a valid date of birth")
	}
}

func TestRussianValidators(t *testing.T) {
	tests := []struct {
		name  string
		fn    func(string) bool
		valid string
		bad   string
	}{
		{"inn10", ValidINN, "7707083893", "7707083894"},
		{"inn12", ValidINN, "500100732259", "500100732250"},
		{"snils", ValidSNILS, "112-233-445 95", "112-233-445 96"},
		{"passport", ValidPassportRF, "4510 123456", "1111111111"},
		{"ogrn", ValidOGRN, "1027700132195", "1027700132196"},
		{"ogrnip", ValidOGRNIP, "304500116000157", "304500116000158"},
		{"kpp", ValidKPP, "773601001", "7736-01001"},
		{"cyrillic", ValidCyrillicFullName, "Иванов Иван Иванович", "Ivan Ivanov"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.fn(tt.valid) {
				t.Fatalf("expected valid value")
			}
			if tt.fn(tt.bad) {
				t.Fatalf("expected invalid value")
			}
		})
	}
}

func TestINNRejectsAllZeroValue(t *testing.T) {
	if ValidINN("0000000000") {
		t.Fatal("all-zero INN must be rejected")
	}
}

func TestSQLTypeCompatibility(t *testing.T) {
	if !Compatible("varchar(255)", []string{"text"}) {
		t.Fatal("varchar should be text-compatible")
	}
	if Compatible("boolean", []string{"text", "numeric"}) {
		t.Fatal("boolean should not be text or numeric compatible")
	}
	if !Compatible("jsonb", []string{"json"}) {
		t.Fatal("jsonb should be json-compatible")
	}
}
