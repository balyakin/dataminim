package classify

import (
	"embed"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yaml
var builtinRuleFS embed.FS

type Rule struct {
	ID                 string   `yaml:"id"`
	CategoryGroup      string   `yaml:"category_group"`
	Description        string   `yaml:"description"`
	Severity           string   `yaml:"severity"`
	NamePatterns       []string `yaml:"name_patterns"`
	ExactNamePatterns  []string `yaml:"exact_name_patterns"`
	PathPatterns       []string `yaml:"path_patterns"`
	ExactPathPatterns  []string `yaml:"exact_path_patterns"`
	NameAntiPatterns   []string `yaml:"name_anti_patterns"`
	PathAntiPatterns   []string `yaml:"path_anti_patterns"`
	ApplicableSQLTypes []string `yaml:"applicable_sql_types"`
	ValueValidator     string   `yaml:"value_validator"`
	ValuePatterns      []string `yaml:"value_patterns"`
	ConfidenceBoost    string   `yaml:"confidence_boost"`
	HelpText           string   `yaml:"help_text"`
	Remediation        string   `yaml:"remediation"`

	compiled compiledRule
}

type compiledRule struct {
	namePatterns      []*regexp.Regexp
	exactNamePatterns []*regexp.Regexp
	pathPatterns      []*regexp.Regexp
	exactPathPatterns []*regexp.Regexp
	nameAntiPatterns  []*regexp.Regexp
	pathAntiPatterns  []*regexp.Regexp
	valuePatterns     []*regexp.Regexp
}

type RuleSet struct {
	Rules       []Rule
	CustomPath  string
	Added       []string
	Overridden  []string
	LocalePacks []string
}

var (
	validSeverities  = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	validConfidence  = map[string]bool{"": true, "low": true, "medium": true, "high": true}
	validTypeClasses = map[string]bool{"text": true, "numeric": true, "date": true, "timestamp": true, "boolean": true, "json": true, "uuid": true, "binary": true}
	snakeRE          = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

func LoadRules(customPath string, locales []string) (RuleSet, error) {
	common, err := loadRuleBytes("rules/common.yaml")
	if err != nil {
		return RuleSet{}, err
	}
	merged := map[string]Rule{}
	order := make([]string, 0, len(common))
	for _, r := range common {
		merged[r.ID] = r
		order = append(order, r.ID)
	}
	var loadedLocales []string
	for _, locale := range locales {
		if locale == "ru" {
			ru, err := loadRuleBytes("rules/ru.yaml")
			if err != nil {
				return RuleSet{}, err
			}
			for _, r := range ru {
				if _, exists := merged[r.ID]; !exists {
					order = append(order, r.ID)
				}
				merged[r.ID] = r
			}
			loadedLocales = append(loadedLocales, "ru")
		}
	}
	rs := RuleSet{CustomPath: customPath, LocalePacks: loadedLocales}
	if customPath != "" {
		custom, err := LoadRuleFile(customPath)
		if err != nil {
			return RuleSet{}, err
		}
		for _, r := range custom {
			if _, exists := merged[r.ID]; exists {
				rs.Overridden = append(rs.Overridden, r.ID)
			} else {
				rs.Added = append(rs.Added, r.ID)
				order = append(order, r.ID)
			}
			merged[r.ID] = r
		}
	}
	for _, id := range order {
		r := merged[id]
		if err := validateAndCompileRule(&r); err != nil {
			return RuleSet{}, fmt.Errorf("rule %q: %w", id, err)
		}
		rs.Rules = append(rs.Rules, r)
	}
	sort.Strings(rs.Added)
	sort.Strings(rs.Overridden)
	return rs, nil
}

func LoadRuleFile(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	var rules []Rule
	if err := yaml.Unmarshal(b, &rules); err != nil {
		return nil, fmt.Errorf("parse rules YAML: %w", err)
	}
	seen := map[string]bool{}
	for i := range rules {
		if seen[rules[i].ID] {
			return nil, fmt.Errorf("duplicate rule id %q", rules[i].ID)
		}
		seen[rules[i].ID] = true
		if err := validateAndCompileRule(&rules[i]); err != nil {
			return nil, fmt.Errorf("rule %q: %w", rules[i].ID, err)
		}
	}
	return rules, nil
}

func loadRuleBytes(name string) ([]Rule, error) {
	b, err := builtinRuleFS.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := yaml.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func validateAndCompileRule(r *Rule) error {
	if !snakeRE.MatchString(r.ID) {
		return fmt.Errorf("id must be lowercase snake_case")
	}
	if !snakeRE.MatchString(r.CategoryGroup) {
		return fmt.Errorf("category_group must be lowercase snake_case")
	}
	if strings.TrimSpace(r.Description) == "" {
		return fmt.Errorf("description is required")
	}
	if !validSeverities[r.Severity] {
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	if !validConfidence[r.ConfidenceBoost] {
		return fmt.Errorf("invalid confidence_boost %q", r.ConfidenceBoost)
	}
	if len(r.ApplicableSQLTypes) == 0 {
		return fmt.Errorf("applicable_sql_types is required")
	}
	for _, cls := range r.ApplicableSQLTypes {
		if !validTypeClasses[cls] {
			return fmt.Errorf("invalid SQL type class %q", cls)
		}
	}
	hasSignal := len(r.NamePatterns)+len(r.ExactNamePatterns)+len(r.PathPatterns)+len(r.ExactPathPatterns)+len(r.ValuePatterns) > 0 || r.ValueValidator != ""
	if !hasSignal {
		return fmt.Errorf("at least one name, path, value pattern, or validator is required")
	}
	if r.ValueValidator != "" && !HasValidator(r.ValueValidator) {
		return fmt.Errorf("unknown validator %q", r.ValueValidator)
	}
	var err error
	if r.compiled.namePatterns, err = compilePatterns(r.NamePatterns, true); err != nil {
		return err
	}
	if r.compiled.exactNamePatterns, err = compileExactPatterns(r.ExactNamePatterns, true); err != nil {
		return err
	}
	if r.compiled.pathPatterns, err = compilePatterns(r.PathPatterns, true); err != nil {
		return err
	}
	if r.compiled.exactPathPatterns, err = compileExactPatterns(r.ExactPathPatterns, true); err != nil {
		return err
	}
	if r.compiled.nameAntiPatterns, err = compilePatterns(r.NameAntiPatterns, true); err != nil {
		return err
	}
	if r.compiled.pathAntiPatterns, err = compilePatterns(r.PathAntiPatterns, true); err != nil {
		return err
	}
	if r.compiled.valuePatterns, err = compilePatterns(r.ValuePatterns, false); err != nil {
		return err
	}
	return nil
}

func compilePatterns(patterns []string, insensitive bool) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if insensitive && !strings.HasPrefix(p, "(?") {
			p = "(?i)" + p
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func compileExactPatterns(patterns []string, insensitive bool) ([]*regexp.Regexp, error) {
	exact := make([]string, 0, len(patterns))
	for _, p := range patterns {
		exact = append(exact, "^(?:"+p+")$")
	}
	return compilePatterns(exact, insensitive)
}

func KnownValidators() []string {
	return validatorNames()
}
