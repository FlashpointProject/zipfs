package zipfs

// Some of the functions in this file are adapted from private
// functions in the standard library net/http package.
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileServer returns a HTTP handler that serves
// HTTP requests with the contents of the ZIP file system.
// It provides slightly better performance than the
// http.FileServer implementation because it serves compressed content
// to clients that can accept the "deflate" compression algorithm.
func FileServer(fs *FileSystem, baseAPIPath string, urlPrepend string, isVerbose bool, indexExts []string, mimeExts map[string]string) http.Handler {
	fsVal := []*FileSystem{fs}
	h := &fileHandler{
		fs:          fsVal,
		baseAPIPath: baseAPIPath,
		isVerbose:   isVerbose,
		urlPrepend:  urlPrepend,
		indexExts:   indexExts,
		mimeExts:    mimeExts,
	}

	return h
}

func FileServers(fs []*FileSystem, baseAPIPath string, urlPrepend string, isVerbose bool, indexExts []string, mimeExts map[string]string) http.Handler {
	h := &fileHandler{
		fs:          fs,
		baseAPIPath: baseAPIPath,
		isVerbose:   isVerbose,
		urlPrepend:  urlPrepend,
		indexExts:   indexExts,
		mimeExts:    mimeExts,
	}

	return h
}

func EmptyFileServer(baseAPIPath string, urlPrepend string, isVerbose bool, indexExts []string, baseMountDir string, phpPath string, mimeExts map[string]string, extScriptTypes []string, overrideBases []string, htdocsPath string) http.Handler {
	return &fileHandler{
		baseAPIPath:    baseAPIPath,
		isVerbose:      isVerbose,
		urlPrepend:     urlPrepend,
		indexExts:      indexExts,
		baseMountDir:   baseMountDir,
		phpPath:        phpPath,
		mimeExts:       mimeExts,
		extScriptTypes: extScriptTypes,
		overrideBases:  overrideBases,
		htdocsPath:     htdocsPath,
	}
}

type fileHandler struct {
	fs               []*FileSystem
	baseAPIPath      string
	isVerbose        bool
	urlPrepend       string
	indexExts        []string
	baseMountDir     string
	phpPath          string
	mimeExts         map[string]string
	extScriptTypes   []string
	overrideBases    []string
	htdocsPath       string
	htaccessHandlers map[string]*HtaccessHandler
	htaccessMutex    sync.RWMutex
}

type Mount struct {
	FilePath    *string      `json:"filePath"`
	ArchiveData *ArchiveData `json:"archiveData"`
}

type ArchiveData struct {
	FilePath          string `json:"filePath"`
	CompressionMethod int16  `json:"compressionMethod"`
	Offset            int64  `json:"offset"`
	CompressedLength  int64  `json:"compressedLength"`
	Length            int64  `json:"length"`
}

type MountList struct {
	MountedZips []string `json:"mountedZips"`
}

func (h *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var urlPath = path.Join("/", strings.ToLower(r.URL.Path))
	var basePath = strings.ToLower(h.baseAPIPath)

	if urlPath == path.Join("/", basePath, "/mountzip") {
		h.MountFs(w, r)
		return
	}

	if urlPath == path.Join("/", basePath, "/unmountzip") {
		h.UnMountFs(w, r)
		return
	}

	if urlPath == path.Join("/", basePath, "/listmountzip") {
		h.ListMountedFs(w, r)
		return
	}

	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}

	fileServingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(CtxUsingHtaccess) != nil {
			// Htaccess, map url back to /content/<host>/<path>
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/")
			if r.Context().Value(CtxPerformedRewrite) != nil {
				r.URL.Path = fmt.Sprintf("/content/%s", r.URL.Path)
			} else {
				r.URL.Path = fmt.Sprintf("/content/%s/%s", r.URL.Hostname(), r.URL.Path)
			}
		}
		fmt.Printf("Final Path: %s\n", r.URL.Path)
		serveFiles(w, r, h, path.Clean(r.URL.Path), true, h.phpPath)
	})

	fmt.Printf("Requested URL (minus query): http:/%s\n", r.URL.Path)

	htaccessChain, hasHtaccess := h.GetHtaccessChain(r.URL.Path, fileServingHandler)
	if hasHtaccess {
		// Form new request url for htaccess to work
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/content")
		newUrl, err := url.Parse(fmt.Sprintf("http:/%s", r.URL.Path))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		newUrl.RawQuery = r.URL.RawQuery
		newUrl.Fragment = r.URL.Fragment
		r.URL = newUrl
		r.Host = r.URL.Host

		ctx := context.WithValue(r.Context(), CtxUsingHtaccess, true)
		r = r.WithContext(ctx)

		// fmt.Printf("Htaccess url check: %s\n", r.URL.String())
		htaccessChain.ServeHTTP(w, r)
	} else {
		fileServingHandler.ServeHTTP(w, r)
	}
}

func (h *fileHandler) HTAFileExists(path string) bool {
	path = "/content/" + strings.TrimPrefix(path, "/")
	// fmt.Printf("Check file: %s\n", path)
	for _, fse := range h.fs {
		fii, err := fse.openFileInfo(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			fmt.Printf("Error checking hta file exists?: %s\n", err.Error())
			return false
		}

		if fii.IsDir() {
			return false
		}
		return true
	}
	return false
}

func (h *fileHandler) HTADirExists(path string) bool {
	path = "/content/" + strings.TrimPrefix(path, "/")
	// fmt.Printf("Check dir: %s\n", path)
	for _, fse := range h.fs {
		fii, err := fse.openFileInfo(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			fmt.Printf("Error checking hta dir exists?: %s\n", err.Error())
			return false
		}

		if fii.IsDir() {
			return true
		}
		return false
	}
	return false
}

// Add a ZIP file at runtime.
func (h *fileHandler) MountFs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fmt.Printf("Error (MountFs): Invalid request, not a POST")
		http.Error(w, "POST request expected.", http.StatusBadRequest)
		return
	}

	var m Mount
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		fmt.Printf("Error (MountFs): %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var newFS *FileSystem

	if m.FilePath != nil {
		// Ensure the zip is within the base directory
		var zipPath string
		if filepath.IsAbs(*m.FilePath) {
			zipPath = path.Clean(*m.FilePath)
		} else {
			zipPath = path.Join(h.baseMountDir, *m.FilePath)
			zipPath = path.Clean(zipPath)
		}
		if !strings.HasPrefix(zipPath, h.baseMountDir) {
			fmt.Printf("Error (MountFs): Illegal path access (%s) %s", *m.FilePath, zipPath)
			http.Error(w, "Illegal path access", http.StatusBadRequest)
			return
		}

		// Prevent duplicate mounts
		for _, fse := range h.fs {
			if fse.givenPath == zipPath {
				fmt.Printf("Error (MountFs Zip): Zip already mounted (%s) %s", *m.FilePath, zipPath)
				makeJsonResponse(w, SimpleResponseData{
					Message: "Zip file already mounted!",
				}, http.StatusOK)
				return
			}
		}

		fmt.Printf("Mounting Zip: %s\n", zipPath)
		var fpErr error
		newFS, fpErr = New(zipPath)
		if fpErr != nil {
			fmt.Printf("Error (MountFs Zip): %s\n", fpErr.Error())
			http.Error(w, fpErr.Error(), http.StatusNotFound)
			return
		}

		if h.isVerbose {
			fmt.Printf("Zip Mounted: %s\n", zipPath)
		}
	} else if m.ArchiveData != nil {
		var fpErr error
		newFS, fpErr = NewArchiveData(*m.ArchiveData)
		if fpErr != nil {
			fmt.Printf("Error (MountFs Archive): %s\n", fpErr.Error())
			http.Error(w, fpErr.Error(), http.StatusNotFound)
			return
		}

		if h.isVerbose {
			fmt.Printf("Archive Zip Mounted: %s\n", m.ArchiveData.FilePath)
		}
	}

	htaccessCount := 0
	htaccessFiles := make(map[string][]byte)

	for _, f := range newFS.fileInfos {
		fileName := filepath.Base(f.name)

		if fileName == ".htaccess" {
			// Read .htaccess content from zip
			reader, err := f.zipFile.Open()
			if err != nil {
				fmt.Printf("Error (MountFs) - Failed to open .htaccess: %s\n", err.Error())
				continue
			}

			content, err := io.ReadAll(reader)
			reader.Close()

			if err != nil {
				fmt.Printf("Error (MountFs) - Failed to read .htaccess: %s\n", err.Error())
				continue
			}

			// Get directory path (remove filename)
			dirPath := filepath.Dir(f.name)
			// Normalize path (remove "content/" prefix if present)
			dirPath = strings.TrimPrefix(dirPath, "content\\")
			dirPath = strings.TrimPrefix(dirPath, "\\")

			htaccessFiles[dirPath] = content
			htaccessCount++

			if h.isVerbose {
				fmt.Printf("Found .htaccess in: %s\n", dirPath)
			}
		}
	}

	// Parse .htaccess files and create handlers
	if htaccessCount > 0 {
		h.htaccessMutex.Lock()
		if h.htaccessHandlers == nil {
			h.htaccessHandlers = make(map[string]*HtaccessHandler)
		}

		for dirPath, content := range htaccessFiles {
			dirPath := "content" + string(os.PathSeparator) + dirPath
			// Write content to temporary file for parsing
			tmpFile, err := os.CreateTemp("", ".htaccess-*")
			if err != nil {
				fmt.Printf("Error (MountFs) - Failed to create temp .htaccess: %s\n", err.Error())
				continue
			}

			_, err = tmpFile.Write(content)
			tmpFile.Close()

			if err != nil {
				fmt.Printf("Error (MountFs) - Failed to write temp .htaccess: %s\n", err.Error())
				os.Remove(tmpFile.Name())
				continue
			}

			// Parse .htaccess file
			fileExistsFunc := FileExistsFunc(h.HTAFileExists)
			dirExistsFunc := DirExistsFunc(h.HTADirExists)
			handler, err := CreateHtaccessHandler(tmpFile.Name(), nil, &fileExistsFunc, &dirExistsFunc)
			os.Remove(tmpFile.Name()) // Clean up temp file

			if err != nil {
				fmt.Printf("Error (MountFs) - Failed to parse .htaccess at %s: %s\n", dirPath, err.Error())
				continue
			}

			h.htaccessHandlers[dirPath] = handler

			if h.isVerbose {
				fmt.Printf("Parsed .htaccess for: %s (%d rules)\n", dirPath, len(handler.Rules))
			}
		}

		h.htaccessMutex.Unlock()
		fmt.Printf("Loaded %d .htaccess files\n", htaccessCount)
	}

	// Find all files ending with a script extension and copy them to htdocs - Assists with file related PHP calls to other PHP files
	count := 0
	for _, f := range newFS.fileInfos {
		if checkForPhp(f.name, h.extScriptTypes) {
			extractPath := path.Clean(path.Join(h.htdocsPath, strings.TrimPrefix(f.name, "content/")))
			if h.isVerbose {
				fmt.Printf("Extracting PHP file: %s\n", extractPath)
			}

			// Create the destination directory
			err := os.MkdirAll(filepath.Dir(extractPath), os.ModePerm)
			if err != nil {
				fmt.Printf("Error (MountFs): %s\n", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Open the file to write to
			outFile, err := os.Create(extractPath)
			if err != nil {
				fmt.Printf("Error (MountFs) - Failed to make HTDOCS Folder: %s\n", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer outFile.Close()

			// Open PHP file from Zip and copy
			reader, err := f.zipFile.Open()
			if err != nil {
				fmt.Printf("Error (MountFs) - Failed to open Zipped file content: %s\n", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer reader.Close()

			_, err = io.Copy(outFile, reader)
			if err != nil {
				fmt.Printf("Error (MountFs) - Failed to copy Zipped file content: %s\n", err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			count++
		}
	}
	if count > 0 {
		fmt.Printf("Extracted %d PHP files to %s\n", count, h.htdocsPath)
	}

	h.fs = append(h.fs, newFS)
	makeJsonResponse(w, SimpleResponseData{
		Message: "Zip file mounted!",
	}, http.StatusOK)
}

// Remove a ZIP file at runtime.
func (h *fileHandler) UnMountFs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fmt.Printf("Error (UnMountFs): Invalid request, not a POST\n")
		http.Error(w, "POST request expected.", http.StatusBadRequest)
		return
	}

	var m Mount
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		fmt.Printf("Error (UnMountFs): %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Ensure the zip is within the base directory
	var zipPath string
	if filepath.IsAbs(*m.FilePath) {
		zipPath = path.Clean(*m.FilePath)
	} else {
		zipPath = path.Join(h.baseMountDir, *m.FilePath)
		zipPath = path.Clean(zipPath)
	}
	if !strings.HasPrefix(zipPath, h.baseMountDir) {
		fmt.Printf("Error (MountFs): Illegal path access (%s) %s", *m.FilePath, zipPath)
		http.Error(w, "Illegal path access", http.StatusBadRequest)
		return
	}

	//Loop through and remove the zip requested
	fmt.Printf("UnMounting Zip: %s\n", zipPath)
	var found = false
	for i := len(h.fs) - 1; i >= 0; i-- {
		if h.fs[i].givenPath == zipPath {
			found = true
			err := h.fs[i].Close()
			if err != nil {
				fmt.Printf("Failed to close zip file %s: %s\n", zipPath, err)
			}
			h.fs = append(h.fs[:i], h.fs[i+1:]...)
		}
	}

	if found && h.isVerbose {
		fmt.Printf("Zip UnMounted: %s\n", zipPath)
	}

	makeJsonResponse(w, SimpleResponseData{
		Message: "Zip file unmounted!",
	}, http.StatusOK)
}

// Remove a ZIP file at runtime.
func (h *fileHandler) ListMountedFs(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fmt.Printf("Error (ListMountedFs): Invalid request, not a GET\n")
		http.Error(w, "GET request expected.", http.StatusBadRequest)
		return
	}

	var ml MountList
	for _, fse := range h.fs {
		ml.MountedZips = append(ml.MountedZips, fse.givenPath)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ml)
}

func (h *fileHandler) GetHtaccessChain(requestPath string, finalHandler http.Handler) (http.Handler, bool) {
	// println("Matching ", requestPath)
	h.htaccessMutex.RLock()
	defer h.htaccessMutex.RUnlock()
	return BuildHtaccessChain(h.htaccessHandlers, requestPath, finalHandler)
}

func BuildHtaccessChain(htaccessHandlers map[string]*HtaccessHandler, requestPath string, finalHandler http.Handler) (http.Handler, bool) {
	if len(htaccessHandlers) == 0 {
		return finalHandler, false // No .htaccess, return final handler directly
	}

	// Find all .htaccess files that apply to this path
	var applicablePaths []string

	parts := strings.Split(requestPath, "/")
	currentPath := ""
	applicablePaths = append(applicablePaths, currentPath)

	for _, part := range parts {
		if part == "" {
			continue
		}
		currentPath = filepath.Join(currentPath, part)
		applicablePaths = append(applicablePaths, currentPath)
	}

	// Collect handlers that exist for these paths
	var handlers []*HtaccessHandler
	for _, p := range applicablePaths {
		if handler, exists := htaccessHandlers[p]; exists {
			handlers = append(handlers, handler)
		}
	}

	if len(handlers) == 0 {
		return finalHandler, false // No applicable .htaccess, return final handler
	}

	// Chain handlers from deepest to root, with finalHandler at the end
	chainedHandler := finalHandler
	for i := len(handlers) - 1; i >= 0; i-- {
		// Clone the handler to avoid modifying the cached one
		handlerCopy := *handlers[i]
		handlerCopy.Next = chainedHandler
		chainedHandler = &handlerCopy
	}

	return chainedHandler, true
}

// name is '/'-separated, not filepath.Separator.
func serveFiles(w http.ResponseWriter, r *http.Request, h *fileHandler, name string, redirect bool, phpPath string) {
	//If a file is attempting to be served, but no zips are available
	//We want to fail gracefully.
	const indexPage = "/index.html"

	// redirect .../index.html to .../
	// can't use Redirect() because that would make the path absolute,
	// which would be a problem running under StripPrefix
	if strings.HasSuffix(r.URL.Path, indexPage) {
		localRedirect(w, r, "./")
		return
	}

	var fi *fileInfo
	var fsVal *FileSystem
	var errVal error

	var errMsg string
	var errCode int
	var errFlag = false

	// Check for file overrides
	for _, overrideBase := range h.overrideBases {
		cleanName, _ := url.PathUnescape(strings.ToLower(path.Clean(name)))
		trimmedName := strings.TrimLeft(cleanName, "/")
		// Remove content prefix, not needed when querying local files
		trimmedName = strings.TrimPrefix(trimmedName, "content/")

		localFile := path.Join(overrideBase, trimmedName)

		stats, err := os.Stat(localFile)
		if err != nil {
			continue
		}

		var foundFile *os.File = nil

		if stats.IsDir() {
			for _, extension := range h.indexExts {
				// use contents of index.html for directory, if present
				index := path.Join(strings.TrimPrefix(localFile, "/"), "/index."+extension)
				file, err := os.Open(index)
				if err == nil {
					foundFile = file
					defer foundFile.Close()
					break
				}
			}
		} else {
			file, err := os.Open(localFile)
			if err == nil {
				foundFile = file
				defer foundFile.Close()
			}
		}

		// Found a file, return it
		if foundFile != nil {
			//Now that we have a file, override the mime-type if it on the list
			mimeOverride, ok := h.mimeExts[strings.ToLower(filepath.Ext(path.Base(foundFile.Name())))]
			if ok {
				w.Header().Set("Content-Type", mimeOverride)
			}

			// serveContent will check modification time and ETag
			w.Header().Set("ZIPSVR_FILENAME", foundFile.Name())
			stats, err := os.Stat(foundFile.Name())
			if err != nil {
				continue
			}
			fmt.Printf("Serving override file: %s\n", foundFile.Name())
			http.ServeContent(w, r, foundFile.Name(), stats.ModTime(), foundFile)
			return
		}
	}

	if len(h.fs) == 0 {
		http.Error(w, "File not found, no ZIP is added.", http.StatusNotFound)
		return
	}

	// Loop through the files in order to find the first match
	for _, fse := range h.fs {
		errFlag = false
		errVal = nil
		fii, err := fse.openFileInfo(name)
		if err != nil {
			errVal = err
		}
		fsVal = fse
		fi = fii

		//If we did not find a file above it will note the error and
		//move onto the next zip to see if the file is there.
		if errVal != nil {
			errFlag = true
			errMsg, errCode = toHTTPError(errVal)
			continue
		}

		if redirect {
			// redirect to canonical path: / at end of directory url
			// r.URL.Path always begins with /
			url := r.URL.Path
			if fi.IsDir() {
				if url[len(url)-1] != '/' {
					localRedirect(w, r, path.Base(url)+"/")
					return
				}
			} else {
				if url[len(url)-1] == '/' {
					localRedirect(w, r, "../"+path.Base(url))
					return
				}
			}
		}

		//Loop through all available extensions and attempt to open them.
		if fi.IsDir() {
			for _, extension := range h.indexExts {
				// use contents of index.html for directory, if present
				index := path.Join(strings.TrimPrefix(name, "/"), "/index."+extension)
				fii, err := fsVal.openFileInfo(index)
				if err == nil {
					fi = fii
				}
			}
		}

		// Still a directory? (we didn't find an index.html file)
		if fi.IsDir() {
			// Unlike the standard library implementation, directory
			// listing is prohibited.
			errFlag = true
			errMsg = "Forbidden"
			errCode = http.StatusForbidden
			continue
		}

		//Now that we have a file, override the mime-type if it on the list
		mimeOverride, ok := h.mimeExts[strings.ToLower(filepath.Ext(path.Base(fi.Name())))]
		if ok {
			w.Header().Set("Content-Type", mimeOverride)
		}

		// serveContent will check modification time and ETag
		w.Header().Set("ZIPSVR_FILENAME", fi.name)

		//If the default value exists, send it over to be used, otherwise use default functionality.
		mimeDefaultOverride, defExists := h.mimeExts["default"]
		if defExists {
			serveContent(w, r, fsVal, fi, phpPath, h.htdocsPath, h.extScriptTypes, &mimeDefaultOverride)
		} else {
			serveContent(w, r, fsVal, fi, phpPath, h.htdocsPath, h.extScriptTypes, nil)
		}
		return
	}

	if errFlag {
		http.Error(w, errMsg, errCode)
		return
	}
}

func serveContent(w http.ResponseWriter, r *http.Request, fs *FileSystem, fi *fileInfo, phpPath string, htdocsPath string, extScriptTypes []string, defaultMime *string) {
	if checkLastModified(w, r, fi.ModTime()) {
		return
	}

	// Set the Etag header in the response before calling checkETag.
	// The checkETag function obtains the files ETag from the response header.
	w.Header().Set("Etag", calcEtag(fi.zipFile))
	rangeReq, done := checkETag(w, r, fi.ModTime())
	if done {
		return
	}
	if rangeReq != "" {
		// Range request requires seeking, so at this point create a temporary
		// file and let the standard library serve it.
		f := fi.openReader(r.URL.Path)
		defer f.Close()
		f.createTempFile()
		http.ServeContent(w, r, fi.Name(), fi.ModTime(), f.file)
		return
	}

	setContentType(w, fi.Name(), defaultMime)

	switch fi.zipFile.Method {
	case zip.Deflate:
		fallthrough
	case zip.Store:
		serveIdentity(w, r, fi, phpPath, htdocsPath, extScriptTypes)
	default:
		http.Error(w, fmt.Sprintf("unsupported zip method: %d", fi.zipFile.Method), http.StatusInternalServerError)
	}
}

// serveIdentity serves a zip file in identity content encoding .
func serveIdentity(w http.ResponseWriter, r *http.Request, fi *fileInfo, phpPath string, htdocsPath string, extScriptTypes []string) {
	// TODO: need to check if the client explicitly refuses to accept
	// identity encoding (Accept-Encoding: identity;q=0), but this is
	// going to be very rare.

	// Divert php requests
	if phpPath != "" && checkForPhp(fi.name, extScriptTypes) && r.Header.Get("DISABLE_PHP") != "1" {
		fileName := strings.TrimPrefix(fi.name, "content/")
		// Run the file from the htdocs directory instead
		htdocsFile := path.Clean(path.Join(htdocsPath, fileName))
		fmt.Printf("Executing PHP Script: %s\n", fileName)
		Cgi(w, r, phpPath, htdocsFile)
		return
	}

	zf := fi.zipFile
	reader, err := zf.Open()
	if err != nil {
		msg, code := toHTTPError(err)
		http.Error(w, msg, code)
		return
	}
	defer reader.Close()

	size := zf.FileInfo().Size()
	w.Header().Del("Content-Encoding")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	if r.Method != "HEAD" {
		io.CopyN(w, reader, size)
	}
	fmt.Printf("[Zipfs] Serving Zipped File: %s\n", zf.Name)
}

func setContentType(w http.ResponseWriter, filename string, defaultMime *string) {
	ctypes, haveType := w.Header()["Content-Type"]
	var ctype string

	if !haveType {
		ctype = mime.TypeByExtension(filepath.Ext(path.Base(filename)))
		if ctype == "" {
			// the standard library sniffs content to decide whether it is
			// binary or text, but this requires a ReaderSeeker, and we
			// only have a reader from the zip file. Assume binary.
			// unless the default mime is overridden, then use that!
			if defaultMime == nil {
				ctype = "application/octet-stream"
			} else {
				ctype = *defaultMime
			}
		}
	} else if len(ctypes) > 0 {
		ctype = ctypes[0]
	}

	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
}

// calcEtag calculates an ETag value for a given zip file based on
// the file's CRC and its length.
func calcEtag(f *zip.File) string {
	size := f.UncompressedSize64
	if size == 0 {
		size = f.UncompressedSize64
	}
	etag := uint64(f.CRC32) ^ (size & 0xffffffff << 32)

	// etag should always be in double quotes
	return fmt.Sprintf(`"%x"`, etag)
}

var unixEpochTime = time.Unix(0, 0)

// modtime is the modification time of the resource to be served, or IsZero().
// return value is whether this request is now complete.
func checkLastModified(w http.ResponseWriter, r *http.Request, modtime time.Time) bool {
	if modtime.IsZero() || modtime.Equal(unixEpochTime) {
		// If the file doesn't have a modtime (IsZero), or the modtime
		// is obviously garbage (Unix time == 0), then ignore modtimes
		// and don't process the If-Modified-Since header.
		return false
	}

	// The Date-Modified header truncates sub-second precision, so
	// use mtime < t+1s instead of mtime <= t to check for unmodified.
	if t, err := time.Parse(http.TimeFormat, r.Header.Get("If-Modified-Since")); err == nil && modtime.Before(t.Add(1*time.Second)) {
		h := w.Header()
		delete(h, "Content-Type")
		delete(h, "Content-Length")
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	w.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	return false
}

// checkETag implements If-None-Match and If-Range checks.
//
// The ETag or modtime must have been previously set in the
// ResponseWriter's headers.  The modtime is only compared at second
// granularity and may be the zero value to mean unknown.
//
// The return value is the effective request "Range" header to use and
// whether this request is now considered done.
func checkETag(w http.ResponseWriter, r *http.Request, modtime time.Time) (rangeReq string, done bool) {
	etag := w.Header().Get("Etag")
	rangeReq = r.Header.Get("Range")

	// Invalidate the range request if the entity doesn't match the one
	// the client was expecting.
	// "If-Range: version" means "ignore the Range: header unless version matches the
	// current file."
	// We only support ETag versions.
	// The caller must have set the ETag on the response already.
	if ir := r.Header.Get("If-Range"); ir != "" && ir != etag {
		// The If-Range value is typically the ETag value, but it may also be
		// the modtime date. See golang.org/issue/8367.
		timeMatches := false
		if !modtime.IsZero() {
			if t, err := http.ParseTime(ir); err == nil && t.Unix() == modtime.Unix() {
				timeMatches = true
			}
		}
		if !timeMatches {
			rangeReq = ""
		}
	}

	if inm := r.Header.Get("If-None-Match"); inm != "" {
		// Must know ETag.
		if etag == "" {
			return rangeReq, false
		}

		// TODO(bradfitz): non-GET/HEAD requests require more work:
		// sending a different status code on matches, and
		// also can't use weak cache validators (those with a "W/
		// prefix).  But most users of ServeContent will be using
		// it on GET or HEAD, so only support those for now.
		if r.Method != "GET" && r.Method != "HEAD" {
			return rangeReq, false
		}

		// TODO(bradfitz): deal with comma-separated or multiple-valued
		// list of If-None-match values.  For now just handle the common
		// case of a single item.
		if inm == etag || inm == "*" {
			h := w.Header()
			delete(h, "Content-Type")
			delete(h, "Content-Length")
			w.WriteHeader(http.StatusNotModified)
			return "", true
		}
	}
	return rangeReq, false
}

// toHTTPError returns a non-specific HTTP error message and status code
// for a given non-nil error value. It's important that toHTTPError does not
// actually return err.Error(), since msg and httpStatus are returned to users,
// and historically Go's ServeContent always returned just "404 Not Found" for
// all errors. We don't want to start leaking information in error messages.
func toHTTPError(err error) (msg string, httpStatus int) {
	if pathErr, ok := err.(*os.PathError); ok {
		err = pathErr.Err
	}
	if os.IsNotExist(err) {
		return "404 page not found", http.StatusNotFound
	}
	if os.IsPermission(err) {
		return "403 Forbidden", http.StatusForbidden
	}
	// Default:
	return "500 Internal Server Error", http.StatusInternalServerError
}

// localRedirect gives a Moved Permanently response.
// It does not convert relative paths to absolute paths like Redirect does.
func localRedirect(w http.ResponseWriter, r *http.Request, newPath string) {
	if q := r.URL.RawQuery; q != "" {
		newPath += "?" + q
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(http.StatusMovedPermanently)
}

type SimpleResponseData struct {
	Message string `json:"msg"`
}

func makeJsonResponse(w http.ResponseWriter, data interface{}, status int) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

func checkForPhp(filePath string, extScriptTypes []string) bool {
	for _, suffix := range extScriptTypes {
		if strings.HasSuffix(filePath, "."+suffix) {
			return true
		}
	}

	return false
}
