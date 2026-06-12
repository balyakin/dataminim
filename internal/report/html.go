package report

import (
	"bytes"
	"fmt"
	"html/template"
	"sort"
	"strings"
)

func WriteHTMLFile(path string, r Report) error {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, r); err != nil {
		return err
	}
	return AtomicWrite(path, buf.Bytes(), 0600)
}

func WriteHTML(w interface{ Write([]byte) (int, error) }, r Report) error {
	NormalizeReport(&r)
	data := htmlData{
		Report:          r,
		MarkdownSummary: markdownSummary(r),
		RiskTables:      htmlRiskTables(r.Tables),
		CriticalGroups:  htmlGroups(filterHTMLFindings(r.Findings, func(f Finding) bool { return f.Severity == "critical" })),
		Groups:          htmlGroups(filterHTMLFindings(r.Findings, func(f Finding) bool { return f.Severity != "critical" })),
	}
	tpl, err := template.New("html").Funcs(template.FuncMap{
		"join": strings.Join,
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tpl.Execute(w, data)
}

type htmlData struct {
	Report          Report
	MarkdownSummary string
	RiskTables      []TableSummary
	CriticalGroups  []htmlGroup
	Groups          []htmlGroup
}

type htmlGroup struct {
	Name     string
	Findings []Finding
}

func htmlGroups(findings []Finding) []htmlGroup {
	groupsByName := map[string][]Finding{}
	for _, f := range findings {
		name := f.Table
		if f.Schema != "" {
			name = f.Schema + "." + f.Table
		}
		groupsByName[name] = append(groupsByName[name], f)
	}
	names := make([]string, 0, len(groupsByName))
	for name := range groupsByName {
		names = append(names, name)
	}
	sort.Strings(names)
	var groups []htmlGroup
	for _, name := range names {
		fs := groupsByName[name]
		sort.Slice(fs, func(i, j int) bool {
			ai := severityRank(fs[i].Severity)
			aj := severityRank(fs[j].Severity)
			if ai == aj {
				return fs[i].Category < fs[j].Category
			}
			return ai > aj
		})
		groups = append(groups, htmlGroup{Name: name, Findings: fs})
	}
	return groups
}

func filterHTMLFindings(findings []Finding, keep func(Finding) bool) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if keep(f) {
			out = append(out, f)
		}
	}
	return out
}

func htmlRiskTables(tables []TableSummary) []TableSummary {
	ranked := make([]TableSummary, 0, len(tables))
	for _, t := range tables {
		if t.Findings > 0 {
			ranked = append(ranked, t)
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].RiskScore == ranked[j].RiskScore {
			if ranked[i].FindingDensity == ranked[j].FindingDensity {
				return ranked[i].Table < ranked[j].Table
			}
			return ranked[i].FindingDensity > ranked[j].FindingDensity
		}
		return ranked[i].RiskScore > ranked[j].RiskScore
	})
	if len(ranked) > 10 {
		ranked = ranked[:10]
	}
	return ranked
}

func markdownSummary(r Report) string {
	return fmt.Sprintf(`# dataminim summary

Source: %s %q
Finished: %s
Findings: %d
Ignored: %d
Critical: %d
High: %d
Warnings: %d
`,
		r.Source.Type, r.Source.Alias, r.FinishedAt, r.Summary.Findings, r.Summary.IgnoredFindings,
		r.Summary.SeverityCounts["critical"], r.Summary.SeverityCounts["high"], r.Summary.WarningCount)
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dataminim report</title>
<style>
:root{color-scheme:light;--text:#17202a;--muted:#5d6975;--line:#d8dee6;--bg:#f7f8fa;--panel:#fff;--crit:#9f1239;--high:#b45309;--med:#0369a1;--low:#4b5563}
*{box-sizing:border-box}body{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:var(--bg);color:var(--text);font-size:14px;line-height:1.45}
header,main{max-width:1180px;margin:0 auto;padding:20px}header{border-bottom:1px solid var(--line);background:var(--panel);max-width:none}header .inner{max-width:1180px;margin:0 auto}
h1{font-size:22px;margin:0 0 6px}h2{font-size:16px;margin:22px 0 10px}.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin:14px 0}.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px}.card strong{display:block;font-size:20px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.filters input,.filters select{height:34px;border:1px solid var(--line);border-radius:4px;background:#fff;padding:0 8px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}th,td{text-align:left;border-bottom:1px solid var(--line);padding:7px 8px;vertical-align:top}th{font-size:12px;color:var(--muted);background:#fbfcfd}
details{background:var(--panel);border:1px solid var(--line);border-radius:6px;margin:10px 0}summary{cursor:pointer;padding:9px 10px;font-weight:600}.finding{border-top:1px solid var(--line);padding:10px;display:grid;gap:6px}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:1px 7px;font-size:12px;margin-right:4px}.critical{color:var(--crit);border-color:#fecdd3}.high{color:var(--high);border-color:#fed7aa}.medium{color:var(--med);border-color:#bae6fd}.low{color:var(--low)}
button{border:1px solid var(--line);background:#fff;border-radius:4px;height:30px;padding:0 8px;cursor:pointer}pre{white-space:pre-wrap;background:#fff;border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto}
@media print{button,.filters{display:none}body{background:#fff}header{border-bottom:1px solid #999}}
</style>
</head>
<body>
<header><div class="inner">
<h1>dataminim report</h1>
<div class="muted">{{.Report.Source.Type}} "{{.Report.Source.Alias}}"{{if .Report.Source.Schema}} schema={{.Report.Source.Schema}}{{end}} · {{.Report.FinishedAt}} · {{.Report.DurationMillis}}ms · {{.Report.Tool.Version}}</div>
</div></header>
<main>
<section class="cards">
<div class="card"><span>Findings</span><strong>{{.Report.Summary.Findings}}</strong></div>
<div class="card"><span>Ignored</span><strong>{{.Report.Summary.IgnoredFindings}}</strong></div>
<div class="card"><span>Tables</span><strong>{{.Report.Summary.TablesScanned}}</strong></div>
<div class="card"><span>Columns</span><strong>{{.Report.Summary.ColumnsChecked}}</strong></div>
<div class="card"><span>JSON paths</span><strong>{{.Report.Summary.JSONPathsChecked}}</strong></div>
<div class="card"><span>Warnings</span><strong>{{.Report.Summary.WarningCount}}</strong></div>
</section>
<section class="filters">
<input id="search" placeholder="Search table, column, path, category" oninput="filterFindings()">
<select id="severity" onchange="filterFindings()"><option value="">Any severity</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select>
<select id="confidence" onchange="filterFindings()"><option value="">Any confidence</option><option>high</option><option>medium</option><option>low</option></select>
</section>
<h2>Highest-Risk Tables</h2>
<table><thead><tr><th>Table</th><th>Risk</th><th>Density</th><th>Findings</th><th>Highest severity</th></tr></thead><tbody>
{{range .RiskTables}}<tr><td>{{if .Schema}}{{.Schema}}.{{end}}{{.Table}}</td><td>{{.RiskScore}}</td><td>{{printf "%.1f" .FindingDensity}}%</td><td>{{.Findings}}</td><td>{{.HighestSeverity}}</td></tr>{{end}}
</tbody></table>
<h2>Markdown Summary</h2>
<button onclick="copyText('summary-md')">Copy</button>
<pre id="summary-md">{{.MarkdownSummary}}</pre>
{{if .CriticalGroups}}
<h2>Critical Findings</h2>
{{range .CriticalGroups}}
<details open><summary>{{.Name}} · {{len .Findings}} critical findings</summary>
{{range .Findings}}
<div class="finding" data-search="{{.Schema}} {{.Table}} {{.Column}} {{.Path}} {{.Category}}" data-severity="{{.Severity}}" data-confidence="{{.Confidence}}">
<div><span class="pill {{.Severity}}">{{.Severity}}</span><span class="pill">{{.Confidence}}</span>{{if .BaselineStatus}}<span class="pill">{{.BaselineStatus}}</span>{{end}}{{if .Ignored}}<span class="pill">ignored</span>{{end}}</div>
<div><strong>{{.Category}}</strong> · {{if .Path}}{{.Path}}{{else}}{{.Column}}{{end}}</div>
<div class="muted">{{join .MatchReasons "; "}}</div>
{{if .MaskedExamples}}<div>Masked examples: {{join .MaskedExamples ", "}}</div>{{end}}
{{if .HelpText}}<div>{{.HelpText}}</div>{{end}}
{{if .Remediation}}<div><strong>Remediation:</strong> {{.Remediation}}</div>{{end}}
<button onclick="copyFinding(this)">Copy Markdown</button>
<template># dataminim finding

Table: {{if .Schema}}{{.Schema}}.{{end}}{{.Table}}
Location: {{if .Path}}{{.Path}}{{else}}{{.Column}}{{end}}
Category: {{.Category}}
Severity: {{.Severity}}
Confidence: {{.Confidence}}
Reason: {{join .MatchReasons "; "}}
</template>
</div>
{{end}}
</details>
{{end}}
{{end}}
<h2>Findings</h2>
{{range .Groups}}
<details open><summary>{{.Name}} · {{len .Findings}} findings</summary>
{{range .Findings}}
<div class="finding" data-search="{{.Schema}} {{.Table}} {{.Column}} {{.Path}} {{.Category}}" data-severity="{{.Severity}}" data-confidence="{{.Confidence}}">
<div><span class="pill {{.Severity}}">{{.Severity}}</span><span class="pill">{{.Confidence}}</span>{{if .BaselineStatus}}<span class="pill">{{.BaselineStatus}}</span>{{end}}{{if .Ignored}}<span class="pill">ignored</span>{{end}}</div>
<div><strong>{{.Category}}</strong> · {{if .Path}}{{.Path}}{{else}}{{.Column}}{{end}}</div>
<div class="muted">{{join .MatchReasons "; "}}</div>
{{if .MaskedExamples}}<div>Masked examples: {{join .MaskedExamples ", "}}</div>{{end}}
{{if .HelpText}}<div>{{.HelpText}}</div>{{end}}
{{if .Remediation}}<div><strong>Remediation:</strong> {{.Remediation}}</div>{{end}}
<button onclick="copyFinding(this)">Copy Markdown</button>
<template># dataminim finding

Table: {{if .Schema}}{{.Schema}}.{{end}}{{.Table}}
Location: {{if .Path}}{{.Path}}{{else}}{{.Column}}{{end}}
Category: {{.Category}}
Severity: {{.Severity}}
Confidence: {{.Confidence}}
Reason: {{join .MatchReasons "; "}}
</template>
</div>
{{end}}
</details>
{{end}}
{{if .Report.Warnings}}<h2>Warnings</h2><table><thead><tr><th>Scope</th><th>Code</th><th>Location</th><th>Message</th></tr></thead><tbody>{{range .Report.Warnings}}<tr><td>{{.Scope}}</td><td>{{.Code}}</td><td>{{.Schema}} {{.Table}} {{.Column}} {{.Path}}</td><td>{{.Message}}</td></tr>{{end}}</tbody></table>{{end}}
</main>
<script>
	function filterFindings(){const q=document.getElementById('search').value.toLowerCase();const s=document.getElementById('severity').value;const c=document.getElementById('confidence').value;document.querySelectorAll('.finding').forEach(function(el){const okq=!q||el.dataset.search.toLowerCase().includes(q);const oks=!s||el.dataset.severity===s;const okc=!c||el.dataset.confidence===c;el.style.display=(okq&&oks&&okc)?'grid':'none';});document.querySelectorAll('details').forEach(function(el){const visible=Array.from(el.querySelectorAll('.finding')).some(function(f){return f.style.display!=='none';});el.style.display=visible?'block':'none';});}
	function copyText(id){navigator.clipboard&&navigator.clipboard.writeText(document.getElementById(id).innerText);}
	function copyFinding(btn){const t=btn.parentElement.querySelector('template');navigator.clipboard&&navigator.clipboard.writeText(t.content.textContent.trim());}
	</script>
</body>
</html>
`
