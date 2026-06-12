package redact

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	keywordPasswordRE = regexp.MustCompile(`(?i)(password|pass|pwd)=('[^']*'|"[^"]*"|\S+)`)
	urlPasswordRE     = regexp.MustCompile(`(?i)(://[^:/?#\s]+:)([^@/?#\s]+)(@)`)
)

func DSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	out := dsn
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" {
		if u.User != nil {
			username := u.User.Username()
			if _, has := u.User.Password(); has {
				u.User = url.UserPassword(username, "REDACTED")
			}
		}
		out = u.String()
	}
	out = keywordPasswordRE.ReplaceAllStringFunc(out, func(s string) string {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return s
		}
		return parts[0] + "=REDACTED"
	})
	out = urlPasswordRE.ReplaceAllString(out, "${1}REDACTED${3}")
	return out
}

func Error(err error, dsn string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if dsn != "" {
		msg = strings.ReplaceAll(msg, dsn, DSN(dsn))
	}
	msg = DSN(msg)
	msg = regexp.MustCompile(`(?i)(password|secret|token)=\S+`).ReplaceAllString(msg, "$1=REDACTED")
	return msg
}

func ContainsPassword(dsn string) bool {
	if dsn == "" {
		return false
	}
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" && u.User != nil {
		_, has := u.User.Password()
		if has {
			return true
		}
	}
	return keywordPasswordRE.MatchString(dsn) || urlPasswordRE.MatchString(dsn)
}
