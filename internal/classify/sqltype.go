package classify

import "strings"

func SQLTypeClasses(sqlType string) map[string]bool {
	t := strings.ToLower(strings.TrimSpace(sqlType))
	t = strings.TrimPrefix(t, "nullable(")
	classes := map[string]bool{}
	switch {
	case strings.Contains(t, "json"):
		classes["json"] = true
		classes["text"] = true
	case strings.Contains(t, "uuid"):
		classes["uuid"] = true
		classes["text"] = true
	case strings.Contains(t, "bool"):
		classes["boolean"] = true
	case strings.Contains(t, "date") && !strings.Contains(t, "update"):
		classes["date"] = true
	case strings.Contains(t, "time"):
		classes["timestamp"] = true
	case strings.Contains(t, "int") || strings.Contains(t, "numeric") || strings.Contains(t, "decimal") || strings.Contains(t, "real") || strings.Contains(t, "double") || strings.Contains(t, "float") || strings.Contains(t, "serial"):
		classes["numeric"] = true
	case strings.Contains(t, "blob") || strings.Contains(t, "bytea") || strings.Contains(t, "binary"):
		classes["binary"] = true
	case strings.Contains(t, "char") || strings.Contains(t, "text") || strings.Contains(t, "clob") || strings.Contains(t, "string") || t == "":
		classes["text"] = true
	default:
		classes["text"] = true
	}
	return classes
}

func Compatible(sqlType string, applicable []string) bool {
	classes := SQLTypeClasses(sqlType)
	for _, cls := range applicable {
		if classes[cls] {
			return true
		}
	}
	return false
}
