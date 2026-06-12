package classify

import (
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Validator func(string) bool

var validators = map[string]Validator{
	"email":               ValidEmail,
	"phone":               ValidPhone,
	"ip":                  ValidIP,
	"credit_card":         ValidCreditCard,
	"dob":                 ValidDOB,
	"latitude":            ValidLatitude,
	"longitude":           ValidLongitude,
	"entropy":             ValidEntropy,
	"password_hash":       ValidPasswordHash,
	"private_key":         ValidPrivateKey,
	"full_name":           ValidFullName,
	"name_token":          ValidNameToken,
	"address":             ValidAddress,
	"zip":                 ValidZIP,
	"user_agent":          ValidUserAgent,
	"inn":                 ValidINN,
	"snils":               ValidSNILS,
	"passport_rf":         ValidPassportRF,
	"ogrn":                ValidOGRN,
	"ogrnip":              ValidOGRNIP,
	"kpp":                 ValidKPP,
	"cyrillic_full_name":  ValidCyrillicFullName,
	"cyrillic_name_token": ValidCyrillicNameToken,
}

func HasValidator(name string) bool {
	_, ok := validators[name]
	return ok
}

func validatorNames() []string {
	names := make([]string, 0, len(validators))
	for name := range validators {
		names = append(names, name)
	}
	sortStrings(names)
	return names
}

func RunValidator(name, value string) bool {
	if v, ok := validators[name]; ok {
		return v(value)
	}
	return false
}

var emailRE = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)

func ValidEmail(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) <= 254 && emailRE.MatchString(s)
}

func ValidPhone(s string) bool {
	raw := strings.TrimSpace(s)
	if len(raw) < 7 || len(raw) > 32 {
		return false
	}
	digits := digitsOnly(raw)
	if len(digits) < 10 || len(digits) > 15 {
		return false
	}
	if allSame(digits) {
		return false
	}
	for _, r := range raw {
		if !(unicode.IsDigit(r) || strings.ContainsRune(" +()-.", r)) {
			return false
		}
	}
	return true
}

func ValidIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

func ValidCreditCard(s string) bool {
	digits := digitsOnly(s)
	if len(digits) < 13 || len(digits) > 19 || allSame(digits) {
		return false
	}
	return LuhnValid(digits)
}

func LuhnValid(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func ValidDOB(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	layouts := []string{
		"2006-01-02",
		"02.01.2006",
		"01/02/2006",
		time.RFC3339,
		"2006-01-02 15:04:05",
	}
	var t time.Time
	var err error
	for _, layout := range layouts {
		t, err = time.Parse(layout, s)
		if err == nil {
			break
		}
	}
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	t = t.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	date := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	min := today.AddDate(-120, 0, 0)
	return !date.After(today) && !date.Before(min)
}

func ValidLatitude(s string) bool {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return err == nil && f >= -90 && f <= 90
}

func ValidLongitude(s string) bool {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return err == nil && f >= -180 && f <= 180
}

var uuidOnlyRE = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func ValidEntropy(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 20 || uuidOnlyRE.MatchString(s) {
		return false
	}
	lettersOrDigits := 0
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			lettersOrDigits++
		}
	}
	if lettersOrDigits < 16 {
		return false
	}
	return shannon(s) >= 3.5
}

var (
	bcryptRE       = regexp.MustCompile(`^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$`)
	argonRE        = regexp.MustCompile(`^\$argon2(id|i|d)\$`)
	pbkdfRE        = regexp.MustCompile(`(?i)^(pbkdf2|scrypt|sha(256|512))[:$]`)
	prefixedSHAHex = regexp.MustCompile(`(?i)^sha(256|512)[:$][a-f0-9]{64,128}$`)
)

func ValidPasswordHash(s string) bool {
	s = strings.TrimSpace(s)
	return bcryptRE.MatchString(s) || argonRE.MatchString(s) || prefixedSHAHex.MatchString(s) || (pbkdfRE.MatchString(s) && len(s) >= 32)
}

func ValidPrivateKey(s string) bool {
	s = strings.TrimSpace(s)
	return strings.Contains(s, "BEGIN PRIVATE KEY") ||
		strings.Contains(s, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(s, "BEGIN OPENSSH PRIVATE KEY")
}

var fullNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z'’-]{1,40}(?:\s+[A-Za-z][A-Za-z'’-]{1,40}){1,3}$`)

func ValidFullName(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) <= 120 && fullNameRE.MatchString(s)
}

var nameTokenRE = regexp.MustCompile(`^[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё'’-]{1,60}$`)

func ValidNameToken(s string) bool {
	s = strings.TrimSpace(s)
	return nameTokenRE.MatchString(s)
}

var (
	latinAddressRE = regexp.MustCompile(`(?i)\b\d{1,6}\s+[\pL0-9.'-]+(?:\s+[\pL0-9.'-]+){0,4}\s+(street|st\.?|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|lane|ln\.?|drive|dr\.?|court|ct\.?)(?:$|[,#]|\s+(apt|apartment|unit|suite|ste)\b)`)
	ruAddressRE    = regexp.MustCompile(`(?i)(?:^|\s)(ул\.?|улица|проспект|пр-кт|шоссе|переулок|пер\.?)\s+[\pL0-9.'-]+(?:\s+[\pL0-9.'-]+){0,4}(?:\s+д\.?\s*\d{1,6}|\s+\d{1,6})(?:$|\s|,)`)
)

func ValidAddress(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 8 || len(s) > 240 {
		return false
	}
	return latinAddressRE.MatchString(s) || ruAddressRE.MatchString(s)
}

var zipRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 -]{2,11}$`)

func ValidZIP(s string) bool {
	s = strings.TrimSpace(s)
	return zipRE.MatchString(s) && strings.ContainsAny(s, "0123456789")
}

func ValidUserAgent(s string) bool {
	s = strings.TrimSpace(s)
	l := strings.ToLower(s)
	return len(s) >= 12 && (strings.Contains(l, "mozilla/") || strings.Contains(l, "chrome/") || strings.Contains(l, "safari/") || strings.Contains(l, "curl/"))
}

func ValidINN(s string) bool {
	d := digitsOnly(s)
	if allSame(d) {
		return false
	}
	switch len(d) {
	case 10:
		return controlDigit(d[:9], []int{2, 4, 10, 3, 5, 9, 4, 6, 8}) == int(d[9]-'0')
	case 12:
		return controlDigit(d[:10], []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}) == int(d[10]-'0') &&
			controlDigit(d[:11], []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}) == int(d[11]-'0')
	default:
		return false
	}
}

func ValidSNILS(s string) bool {
	d := digitsOnly(s)
	if len(d) != 11 || allSame(d) {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (9 - i)
	}
	var check int
	switch {
	case sum < 100:
		check = sum
	case sum == 100 || sum == 101:
		check = 0
	default:
		check = sum % 101
		if check == 100 {
			check = 0
		}
	}
	got, _ := strconv.Atoi(d[9:])
	return check == got
}

func ValidPassportRF(s string) bool {
	d := digitsOnly(s)
	return len(d) == 10 && !allSame(d)
}

func ValidOGRN(s string) bool {
	d := digitsOnly(s)
	if len(d) != 13 || allSame(d) {
		return false
	}
	n, err := strconv.ParseInt(d[:12], 10, 64)
	if err != nil {
		return false
	}
	return int((n%11)%10) == int(d[12]-'0')
}

func ValidOGRNIP(s string) bool {
	d := digitsOnly(s)
	if len(d) != 15 || allSame(d) {
		return false
	}
	n, err := strconv.ParseInt(d[:14], 10, 64)
	if err != nil {
		return false
	}
	return int((n%13)%10) == int(d[14]-'0')
}

var kppRE = regexp.MustCompile(`^[0-9]{4}[0-9A-Z]{2}[0-9]{3}$`)

func ValidKPP(s string) bool {
	return kppRE.MatchString(strings.ToUpper(strings.TrimSpace(s)))
}

var cyrFullNameRE = regexp.MustCompile(`^[А-ЯЁ][а-яё-]{1,40}(?:\s+[А-ЯЁ][а-яё-]{1,40}){1,3}$`)

func ValidCyrillicFullName(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) <= 180 && cyrFullNameRE.MatchString(s)
}

var cyrNameRE = regexp.MustCompile(`^[А-ЯЁ][а-яё-]{1,40}$`)

func ValidCyrillicNameToken(s string) bool {
	return cyrNameRE.MatchString(strings.TrimSpace(s))
}

func controlDigit(digits string, weights []int) int {
	sum := 0
	for i, w := range weights {
		sum += int(digits[i]-'0') * w
	}
	return (sum % 11) % 10
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

func allSame(s string) bool {
	if s == "" {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

func shannon(s string) float64 {
	counts := map[rune]int{}
	var total float64
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, c := range counts {
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
