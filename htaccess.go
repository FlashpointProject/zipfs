package zipfs

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type contextKey string

const (
	CtxEmulatedUrl contextKey = "emulatedUrl"
)

// RewriteRule represents a single Apache RewriteRule
type RewriteRule struct {
	Pattern      *regexp.Regexp
	Substitution string
	Flags        map[string]string
	Conditions   []RewriteCond
}

// RewriteCond represents a RewriteCond directive
type RewriteCond struct {
	TestString string
	Pattern    *regexp.Regexp
	Flags      map[string]string
}

// HtaccessHandler wraps the parsed .htaccess rules
type HtaccessHandler struct {
	Rules       []RewriteRule
	RewriteBase string
	Next        http.Handler
}

// ParseHTAccess parses a .htaccess file and returns a handler
func CreateHtaccessHandler(filepath string, next http.Handler) (*HtaccessHandler, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open .htaccess: %w", err)
	}
	defer file.Close()

	handler := &HtaccessHandler{
		Rules: []RewriteRule{},
		Next:  next,
	}

	scanner := bufio.NewScanner(file)
	var pendingConditions []RewriteCond

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse RewriteBase
		if strings.HasPrefix(line, "RewriteBase") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				handler.RewriteBase = parts[1]
			}
			continue
		}

		// Parse RewriteCond
		if strings.HasPrefix(line, "RewriteCond") {
			cond, err := parseRewriteCond(line)
			if err != nil {
				return nil, err
			}
			pendingConditions = append(pendingConditions, cond)
			continue
		}

		// Parse RewriteRule
		if strings.HasPrefix(line, "RewriteRule") {
			rule, err := parseRewriteRule(line)
			if err != nil {
				return nil, err
			}

			// Attach pending conditions to this rule
			rule.Conditions = pendingConditions
			pendingConditions = nil

			handler.Rules = append(handler.Rules, rule)
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading .htaccess: %w", err)
	}

	return handler, nil
}

// parseRewriteRule parses a RewriteRule line
func parseRewriteRule(line string) (RewriteRule, error) {
	// RewriteRule pattern substitution [flags]
	parts := splitRewriteLine(line)
	if len(parts) < 3 {
		return RewriteRule{}, fmt.Errorf("invalid RewriteRule: %s", line)
	}

	flags := make(map[string]string)
	if len(parts) >= 4 {
		flagStr := strings.Trim(parts[3], "[]")
		flagList := strings.Split(flagStr, ",")
		for _, flag := range flagList {
			flag = strings.TrimSpace(flag)
			if strings.Contains(flag, "=") {
				kv := strings.SplitN(flag, "=", 2)
				flags[kv[0]] = kv[1]
			} else {
				flags[flag] = "true"
			}
		}
	}

	// Add (?i) prefix for case-insensitive matching if NC flag is present
	patternStr := parts[1]
	if _, hasNC := flags["NC"]; hasNC {
		patternStr = "(?i)" + patternStr
	}

	pattern, err := regexp.Compile(parts[1])
	if err != nil {
		return RewriteRule{}, fmt.Errorf("invalid pattern in RewriteRule: %w", err)
	}

	rule := RewriteRule{
		Pattern:      pattern,
		Substitution: parts[2],
		Flags:        flags,
	}

	return rule, nil
}

// parseRewriteCond parses a RewriteCond line
func parseRewriteCond(line string) (RewriteCond, error) {
	// RewriteCond %{REQUEST_URI} pattern [flags]
	parts := splitRewriteLine(line)
	if len(parts) < 3 {
		return RewriteCond{}, fmt.Errorf("invalid RewriteCond: %s", line)
	}

	flags := make(map[string]string)
	if len(parts) >= 4 {
		flagStr := strings.Trim(parts[3], "[]")
		flagList := strings.Split(flagStr, ",")
		for _, flag := range flagList {
			flag = strings.TrimSpace(flag)
			if strings.Contains(flag, "=") {
				kv := strings.SplitN(flag, "=", 2)
				flags[kv[0]] = kv[1]
			} else {
				flags[flag] = "true"
			}
		}
	}

	// Add (?i) prefix for case-insensitive matching if NC flag is present
	patternStr := parts[2]
	if _, hasNC := flags["NC"]; hasNC {
		patternStr = "(?i)" + patternStr
	}

	pattern, err := regexp.Compile(patternStr)
	if err != nil {
		return RewriteCond{}, fmt.Errorf("invalid pattern in RewriteCond: %w", err)
	}

	cond := RewriteCond{
		TestString: parts[1],
		Pattern:    pattern,
		Flags:      flags,
	}

	return cond, nil
}

// splitRewriteLine splits a rewrite line respecting brackets
func splitRewriteLine(line string) []string {
	var parts []string
	var current strings.Builder
	inBracket := false

	for _, char := range line {
		switch char {
		case '[':
			inBracket = true
			current.WriteRune(char)
		case ']':
			inBracket = false
			current.WriteRune(char)
		case ' ', '\t':
			if inBracket {
				current.WriteRune(char)
			} else if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(char)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// ServeHTTP implements http.Handler
func (h *HtaccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	workingPath := r.URL.Path
	// println("Initial path: ", workingPath)

	for _, rule := range h.Rules {
		// fmt.Printf("Rule %d: Pattern=%s, Substitution=%s, Flags=%v\n",
		// 	i, rule.Pattern.String(), rule.Substitution, rule.Flags)

		// Check conditions first
		condMatches := h.checkConditionsWithCaptures(rule.Conditions, r)
		if condMatches == nil {
			continue
		}

		// Check if pattern matches
		if !rule.Pattern.MatchString(workingPath) {
			continue
		}

		// Perform substitution
		workingPath = rule.Pattern.ReplaceAllString(workingPath, rule.Substitution)

		// Replace %N backreferences from RewriteCond
		for i, match := range condMatches {
			placeholder := fmt.Sprintf("%%%d", i+1)
			workingPath = strings.ReplaceAll(workingPath, placeholder, match)
		}

		// Handle special substitutions
		if workingPath == "-" {
			// Pass through unchanged
			continue
		}

		// Apply RewriteBase if set and path is relative
		if h.RewriteBase != "" && !strings.HasPrefix(workingPath, "/") {
			workingPath = strings.TrimSuffix(h.RewriteBase, "/") + "/" + workingPath
		}

		workingPath = strings.TrimPrefix(workingPath, "/")

		// Handle flags
		if h.handleFlags(w, r, workingPath, rule.Flags) {
			return // Redirect or other terminal action
		}

		// [L] flag - stop processing rules
		if _, hasL := rule.Flags["L"]; hasL {
			break
		}

		// [END] flag - stop all processing
		if _, hasEND := rule.Flags["END"]; hasEND {
			break
		}

		// Update path for next iteration
		// fmt.Printf("After rule applied: %s\n", workingPath)
	}

	// fmt.Printf("All rules applied: %s\n", workingPath)
	r.URL.Path = workingPath

	// Pass to next handler
	if h.Next != nil {
		h.Next.ServeHTTP(w, r)
	} else {
		http.NotFound(w, r)
	}
}

// checkConditionsWithCaptures evaluates conditions and returns captured groups
func (h *HtaccessHandler) checkConditionsWithCaptures(conditions []RewriteCond, r *http.Request) []string {
	var allCaptures []string

	for _, cond := range conditions {
		testValue := h.expandVariables(cond.TestString, r)

		matches := cond.Pattern.FindStringSubmatch(testValue)
		if matches == nil {
			return nil // Condition failed
		}

		// Store captures (skip full match at index 0)
		if len(matches) > 1 {
			allCaptures = append(allCaptures, matches[1:]...)
		}

		// Handle flags
		hasOR := false
		for _, flag := range cond.Flags {
			if flag == "OR" {
				hasOR = true
				break
			}
		}

		if hasOR && len(matches) > 0 {
			continue // OR succeeded, continue to next condition
		}
	}

	return allCaptures
}

// expandVariables expands Apache variables like %{REQUEST_URI}
func (h *HtaccessHandler) expandVariables(str string, r *http.Request) string {
	replacements := map[string]string{
		"%{REQUEST_URI}":      r.RequestURI,
		"%{REQUEST_METHOD}":   r.Method,
		"%{QUERY_STRING}":     r.URL.RawQuery,
		"%{HTTP_HOST}":        r.Host,
		"%{REMOTE_ADDR}":      r.RemoteAddr,
		"%{REQUEST_FILENAME}": r.URL.Path,
		"%{DOCUMENT_ROOT}":    "/", // Configure as needed
		"%{SERVER_NAME}":      r.Host,
		"%{SERVER_PORT}":      "80", // Configure as needed
		"%{HTTPS}": func() string {
			if r.TLS != nil {
				return "on"
			} else {
				return "off"
			}
		}(),
	}

	result := str
	for key, value := range replacements {
		result = strings.ReplaceAll(result, key, value)
	}

	return result
}

func (h *HtaccessHandler) handleFlags(w http.ResponseWriter, r *http.Request, newPath string, flags map[string]string) bool {
	// [R] or [R=code] - Redirect
	if redirect, hasR := flags["R"]; hasR {
		code := 302
		if redirect != "true" {
			if c, err := strconv.Atoi(redirect); err == nil {
				code = c
			}
		}

		redirectURL := newPath
		if !strings.HasPrefix(redirectURL, "http") {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			redirectURL = fmt.Sprintf("%s://%s%s", scheme, r.Host, newPath)
		}

		// [QSD] - Query String Discard (don't append query string)
		_, hasQSD := flags["QSD"]

		// [QSA] - Query String Append
		if _, hasQSA := flags["QSA"]; hasQSA && !hasQSD && r.URL.RawQuery != "" {
			separator := "?"
			if strings.Contains(redirectURL, "?") {
				separator = "&"
			}
			redirectURL += separator + r.URL.RawQuery
		}

		http.Redirect(w, r, redirectURL, code)
		return true
	}

	// ... rest of flags
	return false
}
