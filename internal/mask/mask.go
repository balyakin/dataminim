package mask

import (
	"strings"
	"unicode"
)

func Value(category, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var out string
	switch category {
	case "email":
		out = email(raw)
	case "phone":
		out = phone(raw)
	case "credit_card":
		out = lastDigits(raw, "**** **** **** ", 4)
	case "inn", "snils", "passport_rf", "ogrn", "ogrnip", "kpp":
		out = lastDigits(raw, strings.Repeat("*", max(2, len(digitsOnly(raw))-2)), 2)
	case "password", "password_hash", "secret", "token", "api_key", "private_key":
		out = "[" + category + " length=" + itoa(len(raw)) + "]"
	case "date_of_birth":
		out = "****-**-**"
	case "ip_address":
		out = "***.***.***.***"
	case "geo_latitude", "geo_longitude":
		out = "**.******"
	case "full_name", "first_name", "last_name", "full_name_cyrillic", "patronymic":
		out = name(raw)
	case "postal_address", "street":
		out = "[address length=" + itoa(len(raw)) + "]"
	case "zip":
		out = lastDigits(raw, "***", 2)
	default:
		out = generic(raw)
	}
	if out == raw || strings.Contains(out, raw) {
		return ""
	}
	if isCritical(category) && preservesLongSubstring(out, raw, 5) {
		return ""
	}
	return out
}

func email(raw string) string {
	parts := strings.Split(raw, "@")
	if len(parts) != 2 {
		return "j***@e***"
	}
	local := parts[0]
	domain := parts[1]
	firstLocal := "j"
	if local != "" {
		firstLocal = string([]rune(local)[0])
	}
	firstDomain := "e"
	if domain != "" {
		firstDomain = string([]rune(domain)[0])
	}
	tld := ""
	if idx := strings.LastIndex(domain, "."); idx >= 0 && idx < len(domain)-1 {
		tld = domain[idx:]
	}
	if len(tld) > 5 {
		tld = ""
	}
	return firstLocal + "***@" + firstDomain + "***" + tld
}

func phone(raw string) string {
	d := digitsOnly(raw)
	if len(d) < 2 {
		return "+* *** *** ** **"
	}
	return "+* *** *** ** " + d[len(d)-2:]
}

func lastDigits(raw, prefix string, n int) string {
	d := digitsOnly(raw)
	if len(d) == 0 {
		return prefix + "**"
	}
	if len(d) < n {
		n = len(d)
	}
	return prefix + d[len(d)-n:]
}

func name(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "***"
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		r := []rune(f)
		if len(r) == 0 {
			continue
		}
		out = append(out, string(r[0])+"***")
	}
	return strings.Join(out, " ")
}

func generic(raw string) string {
	if len([]rune(raw)) <= 4 {
		return "***"
	}
	return "[masked length=" + itoa(len(raw)) + "]"
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isCritical(category string) bool {
	switch category {
	case "password", "password_hash", "secret", "token", "api_key", "private_key", "credit_card":
		return true
	default:
		return false
	}
}

func preservesLongSubstring(masked, raw string, threshold int) bool {
	rawRunes := []rune(raw)
	for i := 0; i+threshold <= len(rawRunes); i++ {
		part := string(rawRunes[i : i+threshold])
		if strings.Contains(masked, part) {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
