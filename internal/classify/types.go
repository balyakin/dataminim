package classify

import "strings"

type Confidence int

const (
	ConfidenceNone Confidence = iota
	ConfidenceLow
	ConfidenceMedium
	ConfidenceHigh
)

func ParseConfidence(s string) (Confidence, bool) {
	switch strings.ToLower(s) {
	case "low":
		return ConfidenceLow, true
	case "medium":
		return ConfidenceMedium, true
	case "high":
		return ConfidenceHigh, true
	default:
		return ConfidenceNone, false
	}
}

func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	default:
		return ""
	}
}

func confidenceFromString(s string) Confidence {
	c, _ := ParseConfidence(s)
	return c
}

func confidenceAtLeast(got, min string) bool {
	g, ok := ParseConfidence(got)
	if !ok {
		return false
	}
	m, ok := ParseConfidence(min)
	if !ok {
		return false
	}
	return g >= m
}

func ConfidenceAtLeast(got, min string) bool {
	return confidenceAtLeast(got, min)
}
