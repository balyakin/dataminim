package classify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dataminim/dataminim/internal/mask"
	"github.com/dataminim/dataminim/internal/report"
)

const maxJSONBytes = 65536

type valueMatch struct {
	matched  int
	total    int
	examples []string
	seen     map[string]bool
}

type valueEvidenceLevel int

const (
	valueEvidenceNone valueEvidenceLevel = iota
	valueEvidenceMedium
	valueEvidenceHigh
)

type Classifier struct {
	rules         []Rule
	source        string
	minConfidence string
	noSample      bool
	noExamples    bool
}

type ColumnInput struct {
	Schema  string
	Table   string
	Column  string
	SQLType string
	Samples []string
}

type ColumnResult struct {
	Findings         []report.Finding
	JSONPathsChecked int
	Warnings         []report.ScanWarning
}

func NewClassifier(rules []Rule, source, minConfidence string, noSample, noExamples bool) *Classifier {
	return &Classifier{
		rules:         rules,
		source:        source,
		minConfidence: minConfidence,
		noSample:      noSample,
		noExamples:    noExamples,
	}
}

func (c *Classifier) ClassifyColumn(in ColumnInput) ColumnResult {
	var result ColumnResult
	samples := in.Samples
	if c.noSample {
		samples = nil
	}
	jsonCandidate := !c.noSample && len(in.Samples) > 0 && isJSONCandidate(in.SQLType, in.Samples)
	columnSamples := samples
	columnValueSampled := !c.noSample
	if jsonCandidate {
		columnSamples = nil
		columnValueSampled = false
	}
	result.Findings = append(result.Findings, c.classifyTarget(in, "", columnSamples, columnValueSampled)...)
	if jsonCandidate {
		pathsChecked, warnings, findings := c.classifyJSONPaths(in)
		result.JSONPathsChecked = pathsChecked
		result.Warnings = append(result.Warnings, warnings...)
		result.Findings = append(result.Findings, findings...)
	}
	return result
}

func (c *Classifier) classifyTarget(in ColumnInput, path string, samples []string, valueSampled bool) []report.Finding {
	matcher := func(rule Rule, compatible bool) (int, int, []string) {
		return c.matchValues(rule, compatible, samples)
	}
	return c.classifyTargetWithMatcher(in, path, valueSampled, matcher)
}

func (c *Classifier) classifyTargetWithMatcher(
	in ColumnInput,
	path string,
	valueSampled bool,
	matcher func(Rule, bool) (int, int, []string),
) []report.Finding {
	var findings []report.Finding
	for _, rule := range c.rules {
		compatible := Compatible(in.SQLType, rule.ApplicableSQLTypes)
		nameMatched, exactName, nameAnti := matchName(rule, in.Column)
		pathMatched, exactPath, pathAnti := false, false, false
		if path != "" {
			pathMatched, exactPath, pathAnti = matchPath(rule, path)
		}
		if nameAnti && path == "" {
			nameMatched, exactName = false, false
		}
		if pathAnti {
			pathMatched, exactPath = false, false
		}
		strongSignal := nameMatched || pathMatched || exactName || exactPath
		exactSignal := exactName || exactPath
		matched, total, examples := matcher(rule, compatible)
		conf := computeConfidence(rule, compatible, strongSignal, exactSignal, matched, total, c.noSample, valueSampled)
		if conf == ConfidenceNone || !confidenceAtLeast(conf.String(), c.minConfidence) {
			continue
		}
		if !strongSignal && matched == 0 {
			continue
		}
		reasons := buildReasons(rule, compatible, nameMatched, exactName, pathMatched, exactPath, nameAnti || pathAnti, matched, total)
		if len(reasons) == 0 {
			continue
		}
		f := report.Finding{
			Key:              FindingKey(c.source, in.Schema, in.Table, in.Column, path, rule.ID),
			Schema:           in.Schema,
			Table:            in.Table,
			Column:           in.Column,
			Path:             path,
			SQLType:          in.SQLType,
			Category:         rule.ID,
			CategoryGroup:    rule.CategoryGroup,
			Severity:         rule.Severity,
			Confidence:       conf.String(),
			MatchReasons:     reasons,
			MatchedByName:    nameMatched || pathMatched || exactName || exactPath,
			MatchedByValue:   matched > 0,
			MatchedByEntropy: matched > 0 && rule.ValueValidator == "entropy",
			SampleMatched:    matched,
			SampleTotal:      total,
			MaskedExamples:   examples,
			HelpText:         rule.HelpText,
			Remediation:      rule.Remediation,
		}
		findings = append(findings, f)
	}
	return findings
}

func (c *Classifier) matchValues(rule Rule, compatible bool, samples []string) (int, int, []string) {
	if !compatible || len(samples) == 0 {
		return 0, 0, []string{}
	}
	hasValueSignal := rule.ValueValidator != "" || len(rule.compiled.valuePatterns) > 0
	if !hasValueSignal {
		return 0, len(samples), []string{}
	}
	matched := 0
	examples := []string{}
	seenExamples := map[string]bool{}
	for _, raw := range samples {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		ok := false
		if rule.ValueValidator != "" && RunValidator(rule.ValueValidator, v) {
			ok = true
		}
		if !ok {
			for _, re := range rule.compiled.valuePatterns {
				if re.MatchString(v) {
					ok = true
					break
				}
			}
		}
		if ok {
			matched++
			if !c.noExamples && len(examples) < 3 {
				m := mask.Value(rule.ID, v)
				if m != "" && !seenExamples[m] {
					examples = append(examples, m)
					seenExamples[m] = true
				}
			}
		}
	}
	return matched, len(samples), examples
}

func (c *Classifier) matchSingleValue(rule Rule, compatible bool, raw string, match *valueMatch) {
	if !compatible || !hasValueSignal(rule) {
		return
	}
	v := strings.TrimSpace(raw)
	if v == "" {
		return
	}
	match.total++
	ok := false
	if rule.ValueValidator != "" && RunValidator(rule.ValueValidator, v) {
		ok = true
	}
	if !ok {
		for _, re := range rule.compiled.valuePatterns {
			if re.MatchString(v) {
				ok = true
				break
			}
		}
	}
	if !ok {
		return
	}
	match.matched++
	if c.noExamples || len(match.examples) >= 3 {
		return
	}
	m := mask.Value(rule.ID, v)
	if m == "" {
		return
	}
	if match.seen == nil {
		match.seen = map[string]bool{}
	}
	if !match.seen[m] {
		match.examples = append(match.examples, m)
		match.seen[m] = true
	}
}

func computeConfidence(
	rule Rule,
	compatible bool,
	strongSignal bool,
	exactSignal bool,
	matched int,
	total int,
	noSample bool,
	valueSampled bool,
) Confidence {
	if !compatible && strongSignal {
		return ConfidenceLow
	}
	if noSample {
		if strongSignal {
			if rule.Severity == "critical" && rule.ConfidenceBoost == "high" && exactSignal && compatible {
				return ConfidenceHigh
			}
			return ConfidenceMedium
		}
		return ConfidenceNone
	}
	if !valueSampled {
		if strongSignal {
			return ConfidenceMedium
		}
		return ConfidenceNone
	}
	valueEvidence := classifyValueEvidence(rule, matched, total)
	if strongSignal {
		if valueEvidence >= valueEvidenceHigh {
			return ConfidenceHigh
		}
		return ConfidenceMedium
	}
	switch valueEvidence {
	case valueEvidenceHigh:
		return ConfidenceHigh
	case valueEvidenceMedium:
		return ConfidenceMedium
	default:
		return ConfidenceNone
	}
}

func classifyValueEvidence(rule Rule, matched, total int) valueEvidenceLevel {
	if matched <= 0 || total <= 0 {
		return valueEvidenceNone
	}
	ratio := float64(matched) / float64(total)
	if isChecksumValidator(rule.ValueValidator) {
		if ratio >= 0.95 {
			return valueEvidenceHigh
		}
		return valueEvidenceNone
	}
	if isWeakValueOnlyValidator(rule.ValueValidator) {
		if matched >= 5 && ratio >= 0.4 {
			return valueEvidenceHigh
		}
		return valueEvidenceNone
	}
	if matched >= 5 && ratio >= 0.4 {
		return valueEvidenceHigh
	}
	if matched >= 3 && ratio >= 0.4 {
		return valueEvidenceMedium
	}
	return valueEvidenceNone
}

func hasValueSignal(rule Rule) bool {
	return rule.ValueValidator != "" || len(rule.compiled.valuePatterns) > 0
}

func isChecksumValidator(name string) bool {
	switch name {
	case "credit_card", "inn", "snils", "ogrn", "ogrnip":
		return true
	default:
		return false
	}
}

func isWeakValueOnlyValidator(name string) bool {
	switch name {
	case "phone", "dob", "latitude", "longitude", "zip":
		return true
	case "full_name", "name_token", "address", "passport_rf", "entropy":
		return true
	default:
		return false
	}
}

func buildReasons(rule Rule, compatible, nameMatched, exactName, pathMatched, exactPath, antiMatched bool, matched, total int) []string {
	reasons := []string{}
	switch {
	case exactName:
		reasons = append(reasons, "exact name matched "+rule.ID+" rule")
	case nameMatched:
		reasons = append(reasons, "name matched "+rule.ID+" rule")
	}
	switch {
	case exactPath:
		reasons = append(reasons, "exact json path matched "+rule.ID+" rule")
	case pathMatched:
		reasons = append(reasons, "json path matched "+rule.ID+" rule")
	}
	if !compatible {
		reasons = append(reasons, "SQL type incompatible; confidence capped")
	}
	if antiMatched {
		reasons = append(reasons, "negative name/path pattern suppressed weak signal")
	}
	if total > 0 {
		reasons = append(reasons, fmt.Sprintf("sample validation matched %d/%d values", matched, total))
	}
	return reasons
}

func matchName(rule Rule, name string) (matched, exact, anti bool) {
	for _, re := range rule.compiled.nameAntiPatterns {
		if re.MatchString(name) {
			anti = true
			break
		}
	}
	if anti {
		return false, false, true
	}
	for _, re := range rule.compiled.exactNamePatterns {
		if re.MatchString(name) {
			return true, true, false
		}
	}
	for _, re := range rule.compiled.namePatterns {
		if re.MatchString(name) {
			return true, false, false
		}
	}
	return false, false, false
}

func matchPath(rule Rule, path string) (matched, exact, anti bool) {
	last := path
	if idx := strings.LastIndex(path, "."); idx >= 0 {
		last = path[idx+1:]
	}
	for _, re := range rule.compiled.pathAntiPatterns {
		if re.MatchString(path) || re.MatchString(last) {
			anti = true
			break
		}
	}
	if anti {
		return false, false, true
	}
	for _, re := range rule.compiled.exactPathPatterns {
		if re.MatchString(path) || re.MatchString(last) {
			return true, true, false
		}
	}
	for _, re := range rule.compiled.pathPatterns {
		if re.MatchString(path) || re.MatchString(last) {
			return true, false, false
		}
	}
	return false, false, false
}

func FindingKey(source, schema, table, column, path, category string) string {
	canonical := "source=" + source + "\n" +
		"schema=" + schema + "\n" +
		"table=" + table + "\n" +
		"column=" + column + "\n" +
		"path=" + path + "\n" +
		"category=" + category
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func isJSONCandidate(sqlType string, samples []string) bool {
	classes := SQLTypeClasses(sqlType)
	if classes["json"] {
		return true
	}
	for _, s := range samples {
		s = strings.TrimSpace(s)
		if (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) && json.Valid([]byte(s)) {
			return true
		}
	}
	return false
}

func (c *Classifier) classifyJSONPaths(in ColumnInput) (int, []report.ScanWarning, []report.Finding) {
	paths := map[string]map[string]*valueMatch{}
	var warnings []report.ScanWarning
	for _, raw := range in.Samples {
		if len(raw) > maxJSONBytes {
			warnings = append(warnings, report.ScanWarning{
				Scope: "json", Schema: in.Schema, Table: in.Table, Column: in.Column,
				Code: "json_value_too_large", Message: "skipped JSON value larger than 65536 bytes",
			})
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			continue
		}
		c.walkJSON(paths, in, in.Column, v, 0)
	}
	findings := []report.Finding{}
	for path, matches := range paths {
		matcher := func(rule Rule, compatible bool) (int, int, []string) {
			if !compatible || !hasValueSignal(rule) {
				return 0, 0, []string{}
			}
			match := matches[rule.ID]
			if match == nil {
				return 0, 0, []string{}
			}
			return match.matched, match.total, match.examples
		}
		findings = append(findings, c.classifyTargetWithMatcher(in, path, true, matcher)...)
	}
	return len(paths), warnings, findings
}

func (c *Classifier) walkJSON(paths map[string]map[string]*valueMatch, in ColumnInput, prefix string, v any, depth int) {
	if depth > 2 {
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if k == "" {
				continue
			}
			c.walkJSON(paths, in, prefix+"."+k, child, depth+1)
		}
	case []any:
		for _, child := range x {
			c.walkJSON(paths, in, prefix, child, depth)
		}
	case string:
		c.addJSONScalar(paths, in, prefix, x)
	case float64:
		c.addJSONScalar(paths, in, prefix, fmt.Sprintf("%v", x))
	case bool:
		c.addJSONScalar(paths, in, prefix, fmt.Sprintf("%v", x))
	case nil:
	default:
		c.addJSONScalar(paths, in, prefix, fmt.Sprintf("%v", x))
	}
}

func (c *Classifier) addJSONScalar(paths map[string]map[string]*valueMatch, in ColumnInput, path string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	if paths[path] == nil {
		paths[path] = map[string]*valueMatch{}
	}
	for _, rule := range c.rules {
		compatible := Compatible(in.SQLType, rule.ApplicableSQLTypes)
		if !compatible || !hasValueSignal(rule) {
			continue
		}
		match := paths[path][rule.ID]
		if match == nil {
			match = &valueMatch{}
			paths[path][rule.ID] = match
		}
		c.matchSingleValue(rule, compatible, value, match)
	}
}
