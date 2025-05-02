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
		fmt.Println("Initializing binary database...")
	}
	logger.Info("Initializing binary database")

	// Check if database already exists
	force, _ := cmd.Flags().GetBool("force")
	_, err = os.Stat(cfg.DatabasePath)
	if err == nil && !force {
		return fmt.Errorf("database already exists, use --force to reinitialize")
	}

	// Initialize database
	db, err := audit.NewDatabase(cfg.DatabasePath)
	if err != nil {
		logger.Error("Failed to create database: %v", err)
		return fmt.Errorf("failed to create database: %w", err)
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
		logger.Error("Initial scan failed: %v", err)
		return fmt.Errorf("initial scan failed: %w", err)
	}

	if verboseMode && !quietMode {
		fmt.Println() // New line after progress
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

	// Log initialization
	logger.Audit("Database initialized with %d binaries", len(binaries))

	// Output results
	if !quietMode {
		scanDuration := time.Since(startTime)
		fmt.Printf("Database initialization completed in %s\n", scanDuration)
		fmt.Printf("Added %d binaries to the database\n", len(binaries))
	}

	return nil
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
