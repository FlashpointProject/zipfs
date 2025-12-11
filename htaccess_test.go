package zipfs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test folder config of set of htaccess files and associated test cases to run
type TestConfig struct {
	Name     string            `json:"name"`
	Htaccess map[string]string `json:"htaccess"` // url path => htaccess file name
	// e.g 'www.example.com' => 'root.htaccess' when we're mapping for http://www.example.com/.htaccess
	TestCases []TestCase `json:"test_cases"` // Array of test cases to test against this htaccess set
}

// Individual test case used by a parent test folder config
type TestCase struct {
	Name          string `json:"name"`                   // Name of test case
	RequestURL    string `json:"request_url"`            // Request url to ask for
	RequestMethod string `json:"request_method"`         // Request method
	RedirectUrl   string `json:"redirect_url,omitempty"` // URL we expected to be redirected to (Location header)
}

func TestHtaccessHandler(t *testing.T) {
	testDirs, err := filepath.Glob("testdata/htaccess_*")
	if err != nil {
		t.Fatalf("Failed to find test directories: %v", err)
	}

	if len(testDirs) == 0 {
		t.Skip("No test directories found in testdata/")
	}

	for _, testDir := range testDirs {
		testName := filepath.Base(testDir)
		t.Run(testName, func(t *testing.T) {
			// Read test configuration
			configPath := filepath.Join(testDir, "config.json")
			configData, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("Failed to read config.json: %v", err)
			}

			var config TestConfig
			if err := json.Unmarshal(configData, &config); err != nil {
				t.Fatalf("Failed to parse config.json: %v", err)
			}

			// Create handlers for each htaccess file at specified paths
			handlers := make(map[string]*HtaccessHandler)
			for urlPath, htaccessFile := range config.Htaccess {
				htaccessPath := filepath.Join(testDir, htaccessFile)

				handler, err := CreateHtaccessHandler(htaccessPath, nil)
				if err != nil {
					t.Fatalf("Failed to create handler for %s: %v", htaccessFile, err)
				}
				handlers[urlPath] = handler
			}

			finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Run test cases
			for _, tc := range config.TestCases {
				t.Run(tc.Name, func(t *testing.T) {
					method := tc.RequestMethod
					if method == "" {
						method = "GET"
					}

					regularUrl, err := url.Parse(tc.RequestURL)
					if err != nil {
						t.Fatalf("Invalid request_url: %v", err)
					}
					// Map the URL to how we use them internally e.g /example.com/file.txt
					requestUrl := createContentUrlFromRegularUrl(regularUrl)

					req := httptest.NewRequest(method, requestUrl.String(), nil)
					// println("Req path: ", req.URL.Path)
					htaccessHandler := BuildHtaccessChain(handlers, req.URL.Path, finalHandler)
					rec := httptest.NewRecorder()

					htaccessHandler.ServeHTTP(rec, req)

					// Test redirect status matches
					morphedLocation := rec.Header().Get("Location")
					if morphedLocation != "" && tc.RedirectUrl == "" {
						t.Errorf("Redirect happened but not expected, Location: %q", morphedLocation)
					}
					if morphedLocation == "" && tc.RedirectUrl != "" {
						t.Errorf("Redirect expected but didn't happen, expected Location: %q", tc.RedirectUrl)
					}

					// Test redirect matches
					if tc.RedirectUrl != "" {
						morphedLocationUrl, err := url.Parse(morphedLocation)
						if err != nil {
							t.Fatalf("Invalid response location header: %v", err)
						}

						// Unmap the resulting /example.com/file.txt scheme into http://example.com/file.txt which matches original request
						locationUrl := createRegularUrlFromContentUrl(morphedLocationUrl)
						if locationUrl.String() != tc.RedirectUrl {
							t.Errorf("Expected redirect url %q, got %q", tc.RedirectUrl, locationUrl.String())
						}
					}
				})
			}
		})
	}
}

func createContentUrlFromRegularUrl(baseUrl *url.URL) *url.URL {
	contentPath := "/" + baseUrl.Host + baseUrl.Path

	return &url.URL{
		Scheme:   "http",
		Host:     "localhost",
		Path:     contentPath,
		RawQuery: baseUrl.RawQuery,
		Fragment: baseUrl.Fragment,
	}
}

func createRegularUrlFromContentUrl(contentUrl *url.URL) *url.URL {
	path := strings.TrimPrefix(contentUrl.Path, "/")

	// Extract domain (first path segment)
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 {
		return contentUrl
	}

	host := parts[0]
	remainingPath := "/"
	if len(parts) > 1 {
		remainingPath += parts[1]
	}

	return &url.URL{
		Scheme:   "http",
		Host:     host,
		Path:     remainingPath,
		RawQuery: contentUrl.RawQuery,
		Fragment: contentUrl.Fragment,
	}
}

// hasPrefix checks if path starts with prefix, handling trailing slashes
func hasPrefix(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if len(path) < len(prefix) {
		return false
	}
	if path[:len(prefix)] != prefix {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}
