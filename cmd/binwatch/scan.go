package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/zvdy/go-binwatch/pkg/audit"
	"github.com/zvdy/go-binwatch/pkg/config"
	"github.com/zvdy/go-binwatch/pkg/logging"
	"github.com/zvdy/go-binwatch/pkg/security"
)

func init() {
	// Add flags specific to scan command
	scanCmd.Flags().BoolP("update", "u", true, "update database with current state after scan")
}

// runScan implements the scan command functionality
func runScan(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger, err := logging.NewLogger(cfg.LogPath, true)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Close()

	if !quietMode {
		fmt.Println("Scanning system binaries for changes...")
	}
	logger.Info("Starting binary scan")

	// Check if database exists
	_, err = os.Stat(cfg.DatabasePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("database not found, run 'binwatch init' first")
	}

	// Load database
	db, err := audit.NewDatabase(cfg.DatabasePath)
	if err != nil {
		logger.Error("Failed to open database: %v", err)
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create scanner
	scanner, err := audit.NewScanner(cfg.ScanPaths, cfg.WhitelistedBins)
	if err != nil {
		logger.Error("Failed to create scanner: %v", err)
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	// Progress callback
	progressFunc := func(current, total int) {
		if verboseMode && !quietMode {
			fmt.Printf("Scanning: %d/%d files processed\r", current, total)
		}
	}

	// Scan all binaries
	binaries, err := scanner.ScanAllBinaries(progressFunc)
	if err != nil {
		logger.Error("Scan failed: %v", err)
		return fmt.Errorf("scan failed: %w", err)
	}

	if verboseMode && !quietMode {
		fmt.Println() // New line after progress
	}

	// Compare with stored state
	changes := db.CompareWithCurrent(binaries)

	// Log changes
	logger.LogChanges(changes)

	// Save changes to file for reporting
	changesFile := cfg.DatabasePath[:len(cfg.DatabasePath)-3] + ".changes.json"
	if len(changes) > 0 {
		data, err := json.MarshalIndent(changes, "", "  ")
		if err != nil {
			logger.Error("Failed to marshal changes: %v", err)
		} else {
			if err := os.WriteFile(changesFile, data, 0640); err != nil {
				logger.Error("Failed to save changes file: %v", err)
			} else {
				// Set secure permissions for the changes file
				if err := security.SecureFile(changesFile, 0640, cfg.BinwatchUser); err != nil {
					logger.Warning("Failed to set secure permissions on changes file: %v", err)
				}
			}
		}
	}

	// Update database if requested
	updateDB, _ := cmd.Flags().GetBool("update")
	if updateDB && len(changes) > 0 {
		db.Update(binaries)
		if err := db.Save(); err != nil {
			logger.Error("Failed to update database: %v", err)
			return fmt.Errorf("failed to update database: %w", err)
		}
		logger.Info("Database updated with current binary state")
	}

	// Output results
	if !quietMode {
		scanDuration := time.Since(startTime)
		fmt.Printf("Scan completed in %s\n", scanDuration)
		fmt.Printf("Scanned %d binaries\n", len(binaries))

		if len(changes) > 0 {
			fmt.Printf("Detected %d changes\n", len(changes))
			fmt.Println("Run 'binwatch report' for details")
		} else {
			fmt.Println("No changes detected")
		}
	}

	return nil
}

func init() {
	// Override the Run function with our implementation
	scanCmd.Run = func(cmd *cobra.Command, args []string) {
		if err := runScan(cmd, args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}
