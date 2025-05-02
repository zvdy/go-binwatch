package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Change represents a detected change in a binary
type Change struct {
	Binary       *BinaryInfo `json:"binary"`
	ChangeType   string      `json:"change_type"`
	OldValue     string      `json:"old_value,omitempty"`
	NewValue     string      `json:"new_value,omitempty"`
	DetectedTime time.Time   `json:"detected_time"`
}

// Database stores and retrieves binary information
type Database struct {
	Path     string
	Binaries map[string]*BinaryInfo
}

// NewDatabase creates a new binary database
func NewDatabase(path string) (*Database, error) {
	// Create database directory if it doesn't exist
	dbDir := filepath.Dir(path)
	if err := os.MkdirAll(dbDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db := &Database{
		Path:     path,
		Binaries: make(map[string]*BinaryInfo),
	}

	// Try to load existing database
	if _, err := os.Stat(path); err == nil {
		if err := db.Load(); err != nil {
			return nil, fmt.Errorf("error loading database: %w", err)
		}
	}

	return db, nil
}

// Load reads the database from disk
func (db *Database) Load() error {
	data, err := os.ReadFile(db.Path)
	if err != nil {
		return err
	}

	var binaries []*BinaryInfo
	if err := json.Unmarshal(data, &binaries); err != nil {
		return err
	}

	// Index by path
	db.Binaries = make(map[string]*BinaryInfo)
	for _, bin := range binaries {
		db.Binaries[bin.Path] = bin
	}

	return nil
}

// Save writes the database to disk
func (db *Database) Save() error {
	// Convert map to slice for serialization
	var binaries []*BinaryInfo
	for _, bin := range db.Binaries {
		binaries = append(binaries, bin)
	}

	data, err := json.MarshalIndent(binaries, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := db.Path + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		return err
	}

	// Atomic file replacement for database integrity
	if err := os.Rename(tmpFile, db.Path); err != nil {
		os.Remove(tmpFile)
		return err
	}

	return nil
}

// Update adds or updates binary information in the database
func (db *Database) Update(binaries []*BinaryInfo) {
	for _, bin := range binaries {
		db.Binaries[bin.Path] = bin
	}
}

// Remove removes a binary from the database
func (db *Database) Remove(path string) {
	delete(db.Binaries, path)
}

// CompareWithCurrent compares the given binaries with the stored ones
func (db *Database) CompareWithCurrent(current []*BinaryInfo) []*Change {
	var changes []*Change
	currentMap := make(map[string]*BinaryInfo)

	// Build a map of current binaries
	for _, bin := range current {
		currentMap[bin.Path] = bin
	}

	// Check for new or modified binaries
	for _, currentBin := range current {
		storedBin, exists := db.Binaries[currentBin.Path]

		if !exists {
			// New binary
			changes = append(changes, &Change{
				Binary:       currentBin,
				ChangeType:   "added",
				NewValue:     currentBin.Path,
				DetectedTime: time.Now().UTC(),
			})
			continue
		}

		// Check for modifications
		if currentBin.SHA256Hash != storedBin.SHA256Hash {
			changes = append(changes, &Change{
				Binary:       currentBin,
				ChangeType:   "modified_content",
				OldValue:     storedBin.SHA256Hash,
				NewValue:     currentBin.SHA256Hash,
				DetectedTime: time.Now().UTC(),
			})
		}

		// Check for permission changes
		if currentBin.Permissions != storedBin.Permissions {
			changes = append(changes, &Change{
				Binary:       currentBin,
				ChangeType:   "modified_permissions",
				OldValue:     storedBin.Permissions,
				NewValue:     currentBin.Permissions,
				DetectedTime: time.Now().UTC(),
			})
		}

		// Check for ownership changes
		if currentBin.Owner != storedBin.Owner {
			changes = append(changes, &Change{
				Binary:       currentBin,
				ChangeType:   "modified_owner",
				OldValue:     storedBin.Owner,
				NewValue:     currentBin.Owner,
				DetectedTime: time.Now().UTC(),
			})
		}
	}

	// Check for deleted binaries
	for path, storedBin := range db.Binaries {
		if _, exists := currentMap[path]; !exists {
			changes = append(changes, &Change{
				Binary:       storedBin,
				ChangeType:   "deleted",
				OldValue:     storedBin.Path,
				DetectedTime: time.Now().UTC(),
			})
		}
	}

	return changes
}

// GetSummary returns a summary of the database contents
func (db *Database) GetSummary() map[string]interface{} {
	return map[string]interface{}{
		"total_binaries": len(db.Binaries),
		"last_update":    time.Now().UTC(),
		"database_path":  db.Path,
	}
}
