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
	Flags      []string
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

	pattern, err := regexp.Compile(parts[1])
	if err != nil {
		return RewriteRule{}, fmt.Errorf("invalid pattern in RewriteRule: %w", err)
	}

	rule := RewriteRule{
		Pattern:      pattern,
		Substitution: parts[2],
		Flags:        make(map[string]string),
	}

	// Parse flags [L,R=301,QSA]
	if len(parts) >= 4 {
		flagStr := strings.Trim(parts[3], "[]")
		flags := strings.Split(flagStr, ",")
		for _, flag := range flags {
			flag = strings.TrimSpace(flag)
			if strings.Contains(flag, "=") {
				kv := strings.SplitN(flag, "=", 2)
				rule.Flags[kv[0]] = kv[1]
			} else {
				rule.Flags[flag] = "true"
			}
		}
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

	pattern, err := regexp.Compile(parts[2])
	if err != nil {
		return RewriteCond{}, fmt.Errorf("invalid pattern in RewriteCond: %w", err)
	}

	cond := RewriteCond{
		TestString: parts[1],
		Pattern:    pattern,
		Flags:      []string{},
	}

	// Parse flags
	if len(parts) >= 4 {
		flagStr := strings.Trim(parts[3], "[]")
		cond.Flags = strings.Split(flagStr, ",")
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

	for _, rule := range h.Rules {
		// fmt.Printf("Rule %d: Pattern=%s, Substitution=%s, Flags=%v\n",
		// 	i, rule.Pattern.String(), rule.Substitution, rule.Flags)

		// Check conditions first
		if !h.checkConditions(rule.Conditions, r) {
			continue
		}

		// Check if pattern matches
		if !rule.Pattern.MatchString(workingPath) {
			continue
		}

		// Perform substitution
		newPath := rule.Pattern.ReplaceAllString(workingPath, rule.Substitution)

		// Handle special substitutions
		if newPath == "-" {
			// Pass through unchanged
			continue
		}

		// Apply RewriteBase if set and path is relative
		if h.RewriteBase != "" && !strings.HasPrefix(newPath, "/") {
			newPath = strings.TrimSuffix(h.RewriteBase, "/") + "/" + newPath
		}

		// Handle flags
		if h.handleFlags(w, r, newPath, rule.Flags) {
			return // Redirect or other terminal action
		}

		// Update request path for internal rewrite
		r.URL.Path = newPath
		// fmt.Printf("Rule modified path: %s\n", r.URL.Path)

		// [L] flag - stop processing rules
		if _, hasL := rule.Flags["L"]; hasL {
			break
		}

		// [END] flag - stop all processing
		if _, hasEND := rule.Flags["END"]; hasEND {
			break
		}

		// Update path for next iteration
		workingPath = strings.TrimPrefix(newPath, "/")
	}

	// Pass to next handler
	if h.Next != nil {
		h.Next.ServeHTTP(w, r)
	} else {
		http.NotFound(w, r)
	}
}

// checkConditions evaluates RewriteCond directives
func (h *HtaccessHandler) checkConditions(conditions []RewriteCond, r *http.Request) bool {
	for _, cond := range conditions {
		testValue := h.expandVariables(cond.TestString, r)

		matched := cond.Pattern.MatchString(testValue)

		// Handle [NC] flag (case insensitive)
		for _, flag := range cond.Flags {
			if flag == "NC" || flag == "nocase" {
				matched = cond.Pattern.MatchString(strings.ToLower(testValue))
			}
			// Handle [OR] flag
			if flag == "OR" && matched {
				return true
			}
		}

		if !matched {
			return false
		}
	}
	return true
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
		"%{DOCUMENT_ROOT}":    "/var/www/html", // Configure as needed
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

// handleFlags processes rewrite flags
func (h *HtaccessHandler) handleFlags(w http.ResponseWriter, r *http.Request, newPath string, flags map[string]string) bool {
	// [R] or [R=code] - Redirect
	if redirect, hasR := flags["R"]; hasR {
		code := 302 // Default temporary redirect
		if redirect != "true" {
			if c, err := strconv.Atoi(redirect); err == nil {
				code = c
			}
		}

		// Build redirect URL
		redirectURL := newPath
		if !strings.HasPrefix(redirectURL, "http") {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			redirectURL = fmt.Sprintf("%s://%s%s", scheme, r.Host, newPath)
		}

		// [QSA] - Query String Append
		if _, hasQSA := flags["QSA"]; hasQSA && r.URL.RawQuery != "" {
			separator := "?"
			if strings.Contains(redirectURL, "?") {
				separator = "&"
			}
			redirectURL += separator + r.URL.RawQuery
		}

		http.Redirect(w, r, redirectURL, code)
		return true
	}

	// [F] - Forbidden
	if _, hasF := flags["F"]; hasF {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return true
	}

	// [G] - Gone
	if _, hasG := flags["G"]; hasG {
		http.Error(w, "Gone", http.StatusGone)
		return true
	}

	return false
}
