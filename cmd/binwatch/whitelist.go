package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zvdy/go-binwatch/pkg/config"
	"github.com/zvdy/go-binwatch/pkg/logging"
)

// runWhitelist implements the whitelist command functionality
func runWhitelist(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required (add, remove, or list)")
	}

	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger, err := logging.NewLogger(cfg.LogPath, false)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Close()

	// Process whitelist subcommand
	action := args[0]
	switch action {
	case "add":
		return addToWhitelist(args[1:], cfg, logger)
	case "remove":
		return removeFromWhitelist(args[1:], cfg, logger)
	case "list":
		return listWhitelist(cfg)
	default:
		return fmt.Errorf("unknown subcommand: %s", action)
	}
}

// addToWhitelist adds paths to the whitelist
func addToWhitelist(paths []string, cfg *config.Config, logger *logging.Logger) error {
	if len(paths) == 0 {
		return fmt.Errorf("no paths specified")
	}

	// Check if paths exist
	for _, path := range paths {
		// Allow glob patterns
		if strings.ContainsAny(path, "*?[]") {
			continue
		}

		// For literal paths, check if they exist
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			fmt.Printf("Warning: Path does not exist: %s\n", path)
			// But still allow it to be added
		}
	}

	// Add paths to whitelist, avoiding duplicates
	added := 0
	whitelist := map[string]bool{}
	for _, p := range cfg.WhitelistedBins {
		whitelist[p] = true
	}

	for _, path := range paths {
		absPath := path
		if !filepath.IsAbs(path) && !strings.ContainsAny(path, "*?[]") {
			// Convert to absolute path if it's not a glob pattern
			var err error
			absPath, err = filepath.Abs(path)
			if err != nil {
				return fmt.Errorf("failed to convert to absolute path: %w", err)
			}
		}

		if !whitelist[absPath] {
			cfg.WhitelistedBins = append(cfg.WhitelistedBins, absPath)
			whitelist[absPath] = true
			added++
			logger.Audit("Added path to whitelist: %s", absPath)
		}
	}

	// Sort whitelist for readability
	sort.Strings(cfg.WhitelistedBins)

	// Save config
	if err := config.SaveConfig(cfg, configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Added %d paths to whitelist\n", added)
	return nil
}

// removeFromWhitelist removes paths from the whitelist
func removeFromWhitelist(paths []string, cfg *config.Config, logger *logging.Logger) error {
	if len(paths) == 0 {
		return fmt.Errorf("no paths specified")
	}

	// Convert paths to be removed to absolute paths if needed
	toRemove := make(map[string]bool)
	for _, path := range paths {
		if !filepath.IsAbs(path) && !strings.ContainsAny(path, "*?[]") {
			absPath, err := filepath.Abs(path)
			if err != nil {
				return fmt.Errorf("failed to convert to absolute path: %w", err)
			}
			toRemove[absPath] = true
		} else {
			toRemove[path] = true
		}
	}

	// Remove paths from whitelist
	newWhitelist := []string{}
	removed := 0
	for _, path := range cfg.WhitelistedBins {
		if toRemove[path] {
			removed++
			logger.Audit("Removed path from whitelist: %s", path)
		} else {
			newWhitelist = append(newWhitelist, path)
		}
	}

	cfg.WhitelistedBins = newWhitelist

	// Save config
	if err := config.SaveConfig(cfg, configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Removed %d paths from whitelist\n", removed)
	return nil
}

// listWhitelist displays the current whitelist
func listWhitelist(cfg *config.Config) error {
	if jsonOutput {
		fmt.Println("[")
		for i, path := range cfg.WhitelistedBins {
			if i > 0 {
				fmt.Println(",")
			}
			fmt.Printf("  %q", path)
		}
		fmt.Println("\n]")
	} else {
		if len(cfg.WhitelistedBins) == 0 {
			fmt.Println("Whitelist is empty")
		} else {
			fmt.Printf("Whitelist contains %d entries:\n", len(cfg.WhitelistedBins))
			for i, path := range cfg.WhitelistedBins {
				fmt.Printf("%3d: %s\n", i+1, path)
			}
		}
	}
	return nil
}

func init() {
	// Override the Run function with our implementation
	whitelistCmd.Run = func(cmd *cobra.Command, args []string) {
		if err := runWhitelist(cmd, args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}
