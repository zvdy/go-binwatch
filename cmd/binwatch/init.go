package main

import (
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
	// Add flags specific to init command
	initCmd.Flags().BoolP("force", "f", false, "force reinitialization of the database")
}

// runInit implements the init command functionality
func runInit(cmd *cobra.Command, args []string) error {
	startTime := time.Now()

	// Load configuration and logger
	cfg, logger, err := setupConfigAndLogger()
	if err != nil {
		return err
	}
	defer logger.Close()

	// Print initialization message
	logInitialization(logger)

	// Check if database exists
	force, _ := cmd.Flags().GetBool("force")
	if err := checkDatabaseExists(cfg.DatabasePath, force); err != nil {
		return err
	}

	// Perform scanning operations
	binaries, err := performScan(cfg, logger)
	if err != nil {
		return err
	}

	// Save database and configure security
	if err := saveDatabaseAndSecure(cfg, binaries, logger); err != nil {
		return err
	}

	// Log initialization success
	logger.Audit("Database initialized with %d binaries", len(binaries))

	// Output results
	displayInitResults(startTime, len(binaries))

	return nil
}

// setupConfigAndLogger loads configuration and initializes the logger
func setupConfigAndLogger() (*config.Config, *logging.Logger, error) {
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

// logInitialization logs the initialization process
func logInitialization(logger *logging.Logger) {
	if !quietMode {
		fmt.Println("Initializing binary database...")
	}
	logger.Info("Initializing binary database")
}

// checkDatabaseExists verifies if database already exists
func checkDatabaseExists(dbPath string, force bool) error {
	_, err := os.Stat(dbPath)
	if err == nil && !force {
		return fmt.Errorf("database already exists, use --force to reinitialize")
	}
	return nil
}

// performScan handles the scanning of binaries
func performScan(cfg *config.Config, logger *logging.Logger) ([]*audit.BinaryInfo, error) {
	// Initialize database
	db, err := audit.NewDatabase(cfg.DatabasePath)
	if err != nil {
		logger.Error("Failed to create database: %v", err)
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	// Create scanner
	scanner, err := audit.NewScanner(cfg.ScanPaths, cfg.WhitelistedBins)
	if err != nil {
		logger.Error("Failed to create scanner: %v", err)
		return nil, fmt.Errorf("failed to create scanner: %w", err)
	}

	// Define progress callback
	progressFunc := createProgressCallback()

	// Scan all binaries
	binaries, err := scanner.ScanAllBinaries(progressFunc)
	if err != nil {
		logger.Error("Initial scan failed: %v", err)
		return nil, fmt.Errorf("initial scan failed: %w", err)
	}

	if verboseMode && !quietMode {
		fmt.Println() // New line after progress
	}

	return binaries, nil
}

// createProgressCallback returns a function to display scan progress
func createProgressCallback() func(current, total int) {
	return func(current, total int) {
		if verboseMode && !quietMode {
			fmt.Printf("Scanning: %d/%d files processed\r", current, total)
		}
	}
}

// saveDatabaseAndSecure updates, saves, and secures the database
func saveDatabaseAndSecure(cfg *config.Config, binaries []*audit.BinaryInfo, logger *logging.Logger) error {
	// Initialize database
	db, err := audit.NewDatabase(cfg.DatabasePath)
	if err != nil {
		logger.Error("Failed to create database: %v", err)
		return fmt.Errorf("failed to create database: %w", err)
	}

	// Update database with current binaries
	db.Update(binaries)
	if err := db.Save(); err != nil {
		logger.Error("Failed to save database: %v", err)
		return fmt.Errorf("failed to save database: %w", err)
	}

	// Set secure permissions for the database file
	if err := security.SecureFile(cfg.DatabasePath, 0640, cfg.BinwatchUser); err != nil {
		logger.Warning("Failed to set secure permissions on database: %v", err)
	}

	return nil
}

// displayInitResults outputs the results of initialization
func displayInitResults(startTime time.Time, binariesCount int) {
	if !quietMode {
		scanDuration := time.Since(startTime)
		fmt.Printf("Database initialization completed in %s\n", scanDuration)
		fmt.Printf("Added %d binaries to the database\n", binariesCount)
	}
}

func init() {
	// Override the Run function with our implementation
	initCmd.Run = func(cmd *cobra.Command, args []string) {
		if err := runInit(cmd, args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}
