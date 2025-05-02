package audit

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// BinaryInfo stores information about a scanned binary file
type BinaryInfo struct {
	Path         string    `json:"path"`
	SHA256Hash   string    `json:"sha256"`
	SHA512Hash   string    `json:"sha512"`
	Size         int64     `json:"size"`
	Permissions  string    `json:"permissions"`
	Owner        string    `json:"owner"`
	LastModified time.Time `json:"last_modified"`
	LastScanned  time.Time `json:"last_scanned"`
}

// Scanner handles binary scanning operations
type Scanner struct {
	ScanPaths        []string
	WhitelistedPaths []string
	WhitelistRegexes []*regexp.Regexp
}

// NewScanner creates a new binary scanner
func NewScanner(scanPaths, whitelistedPaths []string) (*Scanner, error) {
	// Compile whitelist patterns into regular expressions
	whitelistRegexes := make([]*regexp.Regexp, 0, len(whitelistedPaths))
	for _, pattern := range whitelistedPaths {
		// Convert glob patterns to regex
		regexPattern := globToRegex(pattern)
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist pattern %s: %w", pattern, err)
		}
		whitelistRegexes = append(whitelistRegexes, re)
	}

	return &Scanner{
		ScanPaths:        scanPaths,
		WhitelistedPaths: whitelistedPaths,
		WhitelistRegexes: whitelistRegexes,
	}, nil
}

// globToRegex converts a glob pattern to a regex pattern
func globToRegex(glob string) string {
	// Escape regex special chars except those used in globs
	special := []string{".", "+", "?", "$", "^", "[", "]", "(", ")", "{", "}", "|", "\\"}
	regex := glob

	for _, ch := range special {
		regex = strings.ReplaceAll(regex, ch, "\\"+ch)
	}

	// Convert glob syntax to regex syntax
	regex = strings.ReplaceAll(regex, "*", ".*")
	regex = strings.ReplaceAll(regex, "?", ".")

	// Anchor the regex
	return "^" + regex + "$"
}

// IsWhitelisted checks if a path matches any whitelist pattern
func (s *Scanner) IsWhitelisted(path string) bool {
	for _, re := range s.WhitelistRegexes {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// ScanBinary scans a single binary file and returns information about it
func (s *Scanner) ScanBinary(path string) (*BinaryInfo, error) {
	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// Skip directories
	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a binary")
	}

	// Calculate file hashes
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Use multiple hash functions simultaneously
	sha256Hash := sha256.New()
	sha512Hash := sha512.New()
	multiWriter := io.MultiWriter(sha256Hash, sha512Hash)

	if _, err := io.Copy(multiWriter, file); err != nil {
		return nil, fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Get file owner using exec (more portable than syscalls)
	cmd := exec.Command("stat", "-c", "%U", path)
	ownerBytes, err := cmd.Output()
	owner := "unknown"
	if err == nil {
		owner = strings.TrimSpace(string(ownerBytes))
	}

	binary := &BinaryInfo{
		Path:         path,
		SHA256Hash:   hex.EncodeToString(sha256Hash.Sum(nil)),
		SHA512Hash:   hex.EncodeToString(sha512Hash.Sum(nil)),
		Size:         info.Size(),
		Permissions:  info.Mode().String(),
		Owner:        owner,
		LastModified: info.ModTime(),
		LastScanned:  time.Now().UTC(),
	}

	return binary, nil
}

// ScanAllBinaries scans all binaries in the configured paths
func (s *Scanner) ScanAllBinaries(progressCallback func(current, total int)) ([]*BinaryInfo, error) {
	var results []*BinaryInfo
	var filesToScan []string

	// First, find all binary files
	for _, scanPath := range s.ScanPaths {
		err := filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Skip files we can't access
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			// Check file permissions (executable)
			if info.Mode()&0111 != 0 {
				// Check if file is whitelisted
				if !s.IsWhitelisted(path) {
					filesToScan = append(filesToScan, path)
				}
			}

			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("error walking path %s: %w", scanPath, err)
		}
	}

	// Then scan each file with progress updates
	totalFiles := len(filesToScan)
	for i, path := range filesToScan {
		if progressCallback != nil {
			progressCallback(i+1, totalFiles)
		}

		binary, err := s.ScanBinary(path)
		if err == nil {
			results = append(results, binary)
		}
	}

	return results, nil
}
