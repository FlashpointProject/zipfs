package zipfs

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type contextKey string

const (
	CtxUsingHtaccess    contextKey = "using-htaccess"
	CtxPerformedRewrite contextKey = "performed-rewrite"
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
	TestString  string
	CondPattern string
	Pattern     *regexp.Regexp
	Flags       map[string]string
}

type FileExistsFunc func(path string) (exists bool)
type DirExistsFunc func(path string) (exists bool)

// HtaccessHandler wraps the parsed .htaccess rules
type HtaccessHandler struct {
	Rules       []RewriteRule
	RewriteBase string
	Next        http.Handler
	fileExists  FileExistsFunc
	dirExists   DirExistsFunc
}

func defaultFileExists(path string) bool {
	return false
}

func defaultDirExists(path string) bool {
	return false
}

// ParseHTAccess parses a .htaccess file and returns a handler
func CreateHtaccessHandler(filepath string, next http.Handler, fileExists *FileExistsFunc, dirExists *DirExistsFunc) (*HtaccessHandler, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open .htaccess: %w", err)
	}
	defer file.Close()

	fileExistsFunc := defaultFileExists
	if fileExists != nil {
		fileExistsFunc = *fileExists
	}

	dirExistsFunc := defaultDirExists
	if dirExists != nil {
		dirExistsFunc = *dirExists
	}

	handler := &HtaccessHandler{
		Rules:      []RewriteRule{},
		Next:       next,
		fileExists: fileExistsFunc,
		dirExists:  dirExistsFunc,
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

	pattern, err := regexp.Compile(patternStr)
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
	// RewriteCond TestString CondPattern [flags]
	parts := splitRewriteLine(line)
	if len(parts) < 3 {
		return RewriteCond{}, fmt.Errorf("invalid RewriteCond: %s", line)
	}

	// Check for bracketed flags e.g [L], [L,QSA]
	flags := make(map[string]string)
	if len(parts) >= 4 {
		flagRawStr := parts[len(parts)-1]
		if strings.HasPrefix(flagRawStr, "[") {
			flagStr := strings.Trim(flagRawStr, "[]")
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
	}

	pattern, err := regexp.Compile(parts[2])
	if err != nil {
		// Validate non-regex?
		pattern = nil
	}

	cond := RewriteCond{
		TestString:  parts[1],
		CondPattern: parts[2],
		Pattern:     pattern,
		Flags:       flags,
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
	workingPath = strings.TrimPrefix(workingPath, "/")
	// println("Initial path: ", workingPath)

	for _, rule := range h.Rules {
		// fmt.Printf("Rule %d: Pattern=%s, Substitution=%s, Flags=%v\n",
		// 	i, rule.Pattern.String(), rule.Substitution, rule.Flags)

		// Evaluate Rule Pattern so we can pass matcher to checkConditions later
		patternMatches := rule.Pattern.FindStringSubmatch(workingPath)
		// fmt.Printf("Pattern match: %v\n", patternMatches)

		// Check conditions first
		condFailure, condMatches := h.checkConditions(rule.Conditions, patternMatches, r)
		if condFailure != nil {
			// fmt.Printf("FAILED COND - TestString: %s, CondPattern: %s, Pattern: %s, Flags:%v\n",
			// 	condFailure.TestString, condFailure.CondPattern, condFailure.Pattern, condFailure.Flags)
			// Condition failed, move to next rule
			continue
		}

		// Check if pattern matches
		if !rule.Pattern.MatchString(workingPath) {
			fmt.Println("Pattern doesn't match rule?")
			continue
		}

		// Add ctx flag for fileserver
		if r.Context().Value(CtxPerformedRewrite) == nil {
			ctx := context.WithValue(r.Context(), CtxPerformedRewrite, true)
			r = r.WithContext(ctx)
		}

		workingPath = rule.Substitution

		// Replace $N backreferences from RewriteRule pattern
		for i, match := range patternMatches {
			placeholder := fmt.Sprintf("$%d", i)
			workingPath = strings.ReplaceAll(workingPath, placeholder, match)
		}

		// Replace %N backreferences from RewriteCond
		for i, match := range condMatches {
			placeholder := fmt.Sprintf("%%%d", i)
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

// checkConditions evaluates conditions and returns captured group
func (h *HtaccessHandler) checkConditions(conditions []RewriteCond, patternMatches []string, r *http.Request) (*RewriteCond, []string) {
	var lastCapture []string
	success := true

	for _, cond := range conditions {
		testValue := h.expandVariables(cond.TestString, r)
		// Backfill %num refs from previous cond captures
		if len(lastCapture) > 0 {
			for i, match := range lastCapture {
				placeholder := fmt.Sprintf("%%%d", i)
				testValue = strings.ReplaceAll(testValue, placeholder, match)
			}
		}
		// Backfill $num refs from rule pattern
		if len(patternMatches) > 0 {
			for i, match := range patternMatches {
				placeholder := fmt.Sprintf("$%d", i)
				testValue = strings.ReplaceAll(testValue, placeholder, match)
			}
		}
		_, hasOR := cond.Flags["OR"]

		condPattern := cond.CondPattern
		negateResult := false
		if strings.HasPrefix(condPattern, "!") && len(condPattern) > 1 {
			negateResult = true
			condPattern = condPattern[1:]
		}
		// Check type of condition
		switch condPattern {
		case "-f":
			// Check file exists
			success = h.fileExists(testValue)
		case "-d":
			// Check directory exists
			success = h.dirExists(testValue)
		default:
			// Assume regex
			matches := cond.Pattern.FindStringSubmatch(testValue)
			if matches == nil && !hasOR && !negateResult {
				// Match failed
				return &cond, nil
			}
			success = matches != nil // Save success of rule

			// Store captures (skip full match at index 0)
			if len(matches) > 1 {
				lastCapture = matches
			}
		}

		if negateResult {
			success = !success
		}

		if !hasOR && !success {
			// Rule failed, not in an OR, skip rule
			return &cond, lastCapture
		}

		// Rule passed, or we're in an OR and it'll resolve on the next conds
	}

	return nil, lastCapture
}

// expandVariables expands Apache variables like %{REQUEST_URI}
func (h *HtaccessHandler) expandVariables(str string, r *http.Request) string {
	replacements := map[string]string{
		"%{REQUEST_URI}":    r.RequestURI,
		"%{REQUEST_METHOD}": r.Method,
		"%{QUERY_STRING}":   r.URL.RawQuery,
		"%{HTTP_HOST}":      r.Host,
		"%{REMOTE_ADDR}":    r.RemoteAddr,
		// This works for reasons beyond my understanding
		"%{REQUEST_FILENAME}": fmt.Sprintf("%s%s", r.URL.Hostname(), r.URL.Path),
		"%{DOCUMENT_ROOT}":    "", // Configure as needed
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
			newPath = strings.TrimPrefix(newPath, "/")
			redirectURL = fmt.Sprintf("%s://%s/%s", scheme, r.Host, newPath)
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

		// fmt.Printf("REDIRECT URL: %s\n", redirectURL)
		http.Redirect(w, r, redirectURL, code)
		return true
	}

	// ... rest of flags
	return false
}
