package zipfs

import (
	"encoding/json"
	"fmt"
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
	TestCases []TestCase `json:"test_cases"`           // Array of test cases to test against this htaccess set
	MockFiles []string   `json:"mock_files,omitempty"` // Mock files for -f flag
	MockDirs  []string   `json:"mock_dirs,omitempty"`  // Mock directories for -d flag
}

// Individual test case used by a parent test folder config
type TestCase struct {
	Name          string `json:"name"`                    // Name of test case
	RequestURL    string `json:"request_url"`             // Request url to ask for
	RequestMethod string `json:"request_method"`          // Request method
	RedirectUrl   string `json:"redirect_url,omitempty"`  // URL we expected to be redirected to (Location header)
	ReturnedFile  string `json:"returned_file,omitempty"` // Path we expected to return
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

			hasMockFile := FileExistsFunc(func(path string) bool {
				path = strings.ReplaceAll(path, "//", "/")
				// fmt.Printf("Testing File: %s\n", path)
				for _, file := range config.MockFiles {
					if file == path {
						return true
					}
				}
				return false
			})

			hasMockDir := DirExistsFunc(func(path string) bool {
				path = strings.ReplaceAll(path, "//", "/")
				fmt.Printf("Testing Dir: %s\n", path)
				for _, dir := range config.MockDirs {
					if dir == path {
						return true
					}
				}
				return false
			})

			// Create handlers for each htaccess file at specified paths
			handlers := make(map[string]*HtaccessHandler)
			for urlPath, htaccessFile := range config.Htaccess {
				htaccessPath := filepath.Join(testDir, htaccessFile)

				handler, err := CreateHtaccessHandler(htaccessPath, nil, &hasMockFile, &hasMockDir)
				if err != nil {
					t.Fatalf("Failed to create handler for %s: %v", htaccessFile, err)
				}
				handlers[urlPath] = handler
			}

			// Run test cases
			for _, tc := range config.TestCases {
				t.Run(tc.Name, func(t *testing.T) {
					actualReturnedFile := ""

					finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						r.URL.Path = "/" + strings.TrimPrefix(r.URL.Path, "/")
						actualReturnedFile = r.URL.Path
						w.WriteHeader(http.StatusOK)
					})

					// fmt.Printf("Test case: %s\n", tc.Name)
					method := tc.RequestMethod
					if method == "" {
						method = "GET"
					}

					requestUrl, err := url.Parse(tc.RequestURL)
					if err != nil {
						t.Fatalf("Invalid request_url: %v", err)
					}

					req := httptest.NewRequest(method, requestUrl.String(), nil)
					htaccessHandler, _ := BuildHtaccessChain(handlers, fmt.Sprintf("%s%s", req.URL.Hostname(), req.URL.Path), finalHandler)
					rec := httptest.NewRecorder()

					htaccessHandler.ServeHTTP(rec, req)
					// fmt.Printf("TEST FILE: %s\n", tc.ReturnedFile)
					// fmt.Printf("RET FILE: %s\n", actualReturnedFile)

					// Test returned file matches
					if tc.ReturnedFile != "" && actualReturnedFile != tc.ReturnedFile {
						t.Errorf("Returned file expected %q, got %q", tc.ReturnedFile, actualReturnedFile)
					}

					// Test redirect status matches
					location := rec.Header().Get("Location")
					if location != "" && tc.RedirectUrl == "" {
						t.Errorf("Redirect happened but not expected, Location: %q", location)
					}
					if location == "" && tc.RedirectUrl != "" {
						t.Errorf("Redirect expected but didn't happen, expected Location: %q", tc.RedirectUrl)
					}

					// Test redirect matches
					if tc.RedirectUrl != "" {
						locationUrl, err := url.Parse(location)
						if err != nil {
							t.Fatalf("Invalid response location header: %v", err)
						}

						// Unmap the resulting /example.com/file.txt scheme into http://example.com/file.txt which matches original request
						if locationUrl.String() != tc.RedirectUrl {
							t.Errorf("Expected redirect url %q, got %q", tc.RedirectUrl, locationUrl.String())
						}
					}
				})
			}
		})
	}
}
