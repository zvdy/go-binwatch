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

	// Load configuration and logger
	cfg, logger, err := setupScanConfigAndLogger()
	if err != nil {
		return err
	}
	defer logger.Close()

	// Print scan message
	logScanStart(logger)

	// Check database existence
	if err := checkDatabaseExistence(cfg.DatabasePath); err != nil {
		return err
	}

	// Perform the scan
	db, binaries, changes, err := performScanAndCompare(cfg, logger)
	if err != nil {
		return err
	}

	// Save changes to file
	err = saveChangesToFile(changes, cfg, logger)
	if err != nil {
		// Just log error but don't fail the operation
		logger.Error("Error while saving changes: %v", err)
	}

	// Update database if needed
	if err := updateDatabaseIfRequested(cmd, db, binaries, changes, logger); err != nil {
		return err
	}

	// Display results
	displayScanResults(startTime, binaries, changes)

	return nil
}

// setupScanConfigAndLogger loads configuration and initializes the logger for scan operations
func setupScanConfigAndLogger() (*config.Config, *logging.Logger, error) {
	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger, err := logging.NewLogger(cfg.LogPath, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	return cfg, logger, nil
}

// logScanStart logs the beginning of the scan operation
func logScanStart(logger *logging.Logger) {
	if !quietMode {
		fmt.Println("Scanning system binaries for changes...")
	}
	logger.Info("Starting binary scan")
}

// checkDatabaseExistence verifies the database file exists
func checkDatabaseExistence(dbPath string) error {
	_, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("database not found, run 'binwatch init' first")
	}
	return nil
}

// performScanAndCompare scans binaries and compares them with the database
func performScanAndCompare(cfg *config.Config, logger *logging.Logger) (*audit.Database, []*audit.BinaryInfo, []*audit.Change, error) {
	// Load database
	db, err := audit.NewDatabase(cfg.DatabasePath)
	if err != nil {
		logger.Error("Failed to open database: %v", err)
		return nil, nil, nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create scanner
	scanner, err := audit.NewScanner(cfg.ScanPaths, cfg.WhitelistedBins)
	if err != nil {
		logger.Error("Failed to create scanner: %v", err)
		return nil, nil, nil, fmt.Errorf("failed to create scanner: %w", err)
	}

	// Define progress callback
	progressFunc := func(current, total int) {
		if verboseMode && !quietMode {
			fmt.Printf("Scanning: %d/%d files processed\r", current, total)
		}
	}

	// Scan all binaries
	binaries, err := scanner.ScanAllBinaries(progressFunc)
	if err != nil {
		logger.Error("Scan failed: %v", err)
		return nil, nil, nil, fmt.Errorf("scan failed: %w", err)
	}

	if verboseMode && !quietMode {
		fmt.Println() // New line after progress
	}

	// Compare with stored state
	changes := db.CompareWithCurrent(binaries)

	// Log changes
	logger.LogChanges(changes)

	return db, binaries, changes, nil
}

// saveChangesToFile saves detected changes to a JSON file
func saveChangesToFile(changes []*audit.Change, cfg *config.Config, logger *logging.Logger) error {
	if len(changes) == 0 {
		return nil // No changes to save
	}

	changesFile := cfg.DatabasePath[:len(cfg.DatabasePath)-3] + ".changes.json"
	data, err := json.MarshalIndent(changes, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal changes: %v", err)
		return err
	}

	if err := os.WriteFile(changesFile, data, 0640); err != nil {
		logger.Error("Failed to save changes file: %v", err)
		return err
	}

	// Set secure permissions for the changes file
	if err := security.SecureFile(changesFile, 0640, cfg.BinwatchUser); err != nil {
		logger.Warning("Failed to set secure permissions on changes file: %v", err)
		return err
	}

	return nil
}

// updateDatabaseIfRequested updates the database if the update flag is true and changes were detected
func updateDatabaseIfRequested(cmd *cobra.Command, db *audit.Database, binaries []*audit.BinaryInfo, changes []*audit.Change, logger *logging.Logger) error {
	updateDB, _ := cmd.Flags().GetBool("update")
	if updateDB && len(changes) > 0 {
		db.Update(binaries)
		if err := db.Save(); err != nil {
			logger.Error("Failed to update database: %v", err)
			return fmt.Errorf("failed to update database: %w", err)
		}
		logger.Info("Database updated with current binary state")
	}
	return nil
}

// displayScanResults shows the scan results to the user
func displayScanResults(startTime time.Time, binaries []*audit.BinaryInfo, changes []*audit.Change) {
	if quietMode {
		return
	}

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

func init() {
	// Override the Run function with our implementation
	scanCmd.Run = func(cmd *cobra.Command, args []string) {
		if err := runScan(cmd, args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}
