package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/zvdy/go-binwatch/pkg/audit"
	"github.com/zvdy/go-binwatch/pkg/config"
	"github.com/zvdy/go-binwatch/pkg/logging"
)

func init() {
	// Add flags specific to report command
	reportCmd.Flags().StringP("since", "s", "", "only show changes since this date (format: YYYY-MM-DD)")
	reportCmd.Flags().StringP("type", "t", "", "filter by change type (added, deleted, modified_content, modified_permissions, modified_owner)")
	reportCmd.Flags().StringP("path", "p", "", "filter by binary path (supports glob patterns)")
	reportCmd.Flags().BoolP("summary-only", "o", false, "show only summary, not individual changes")
}

// runReport implements the report command functionality
func runReport(cmd *cobra.Command, args []string) error {
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

	if !quietMode {
		fmt.Println("Generating binary changes report...")
	}

	// Initialize database
	db, err := audit.NewDatabase(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Get report filters
	sinceStr, _ := cmd.Flags().GetString("since")
	changeType, _ := cmd.Flags().GetString("type")
	pathFilter, _ := cmd.Flags().GetString("path")
	summaryOnly, _ := cmd.Flags().GetBool("summary-only")

	// Parse since date if provided
	var sinceDate time.Time
	if sinceStr != "" {
		sinceDate, err = time.Parse("2006-01-02", sinceStr)
		if err != nil {
			return fmt.Errorf("invalid date format for --since, use YYYY-MM-DD: %w", err)
		}
	}

	// Try to read the last scan changes if they exist
	changesFile := strings.TrimSuffix(cfg.DatabasePath, ".db") + ".changes.json"
	changes, err := loadChangesFile(changesFile)
	if err != nil {
		return fmt.Errorf("failed to load changes file: %w", err)
	}

	// Filter changes based on command flags
	filteredChanges := filterChanges(changes, sinceDate, changeType, pathFilter)

	// Get database summary
	dbSummary := db.GetSummary()

	// Display report
	displayReport(filteredChanges, dbSummary, summaryOnly)

	return nil
}

// loadChangesFile loads the changes from the last scan
func loadChangesFile(path string) ([]*audit.Change, error) {
	// Check if file exists
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return []*audit.Change{}, nil
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read changes file: %w", err)
	}

	// Parse JSON
	var changes []*audit.Change
	if err := json.Unmarshal(data, &changes); err != nil {
		return nil, fmt.Errorf("failed to parse changes file: %w", err)
	}

	return changes, nil
}

// filterChanges applies filters to the changes list
func filterChanges(changes []*audit.Change, since time.Time, changeType, pathPattern string) []*audit.Change {
	if len(changes) == 0 {
		return changes
	}

	var filtered []*audit.Change

	for _, change := range changes {
		// Filter by date if provided
		if !since.IsZero() && change.DetectedTime.Before(since) {
			continue
		}

		// Filter by change type if provided
		if changeType != "" && change.ChangeType != changeType {
			continue
		}

		// Filter by path if provided
		if pathPattern != "" {
			// Quick and simple check - improve with proper glob matching if needed
			if !strings.Contains(change.Binary.Path, pathPattern) {
				continue
			}
		}

		filtered = append(filtered, change)
	}

	// Sort by detection time
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].DetectedTime.After(filtered[j].DetectedTime)
	})

	return filtered
}

// displayReport shows the report in the requested format
func displayReport(changes []*audit.Change, dbSummary map[string]interface{}, summaryOnly bool) {
	// Count types of changes
	changeCounts := countChangeTypes(changes)
	
	// Output in appropriate format
	if jsonOutput {
		outputJSONReport(changes, dbSummary, changeCounts, summaryOnly)
	} else {
		outputTextReport(changes, dbSummary, changeCounts, summaryOnly)
	}
}

// countChangeTypes counts the occurrences of each change type
func countChangeTypes(changes []*audit.Change) map[string]int {
	counts := map[string]int{
		"added":                0,
		"deleted":              0,
		"modified_content":     0,
		"modified_permissions": 0,
		"modified_owner":       0,
		"total":                len(changes),
	}
	
	for _, change := range changes {
		switch change.ChangeType {
		case "added":
			counts["added"]++
		case "deleted":
			counts["deleted"]++
		case "modified_content":
			counts["modified_content"]++
		case "modified_permissions":
			counts["modified_permissions"]++
		case "modified_owner":
			counts["modified_owner"]++
		}
	}
	
	return counts
}

// outputJSONReport formats and outputs the report in JSON format
func outputJSONReport(changes []*audit.Change, dbSummary map[string]interface{}, changeCounts map[string]int, summaryOnly bool) {
	report := map[string]interface{}{
		"database_summary": dbSummary,
		"changes_summary": changeCounts,
	}

	if !summaryOnly {
		report["changes"] = changes
	}

	jsonData, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(jsonData))
}

// outputTextReport formats and outputs the report in human-readable text format
func outputTextReport(changes []*audit.Change, dbSummary map[string]interface{}, changeCounts map[string]int, summaryOnly bool) {
	// Print report header and database info
	printReportHeader(dbSummary)
	
	// Print changes summary
	printChangesSummary(changeCounts)
	
	// Show detailed changes if requested and we have changes
	if !summaryOnly && len(changes) > 0 {
		printDetailedChanges(changes)
	}
}

// printReportHeader prints the header of the text report
func printReportHeader(dbSummary map[string]interface{}) {
	fmt.Println("BinWatch Audit Report")
	fmt.Println("=====================")
	fmt.Printf("Database Path: %s\n", dbSummary["database_path"])
	fmt.Printf("Total Binaries: %d\n", dbSummary["total_binaries"])
	fmt.Printf("Last Update: %v\n", dbSummary["last_update"])
	fmt.Println()
}

// printChangesSummary prints the summary of changes
func printChangesSummary(counts map[string]int) {
	fmt.Println("Changes Summary")
	fmt.Println("--------------")
	fmt.Printf("Total Changes: %d\n", counts["total"])
	fmt.Printf("  - New Binaries: %d\n", counts["added"])
	fmt.Printf("  - Deleted Binaries: %d\n", counts["deleted"])
	fmt.Printf("  - Modified Content: %d\n", counts["modified_content"])
	fmt.Printf("  - Modified Permissions: %d\n", counts["modified_permissions"])
	fmt.Printf("  - Modified Ownership: %d\n", counts["modified_owner"])
}

// printDetailedChanges prints detailed information about each change
func printDetailedChanges(changes []*audit.Change) {
	fmt.Println("\nDetailed Changes")
	fmt.Println("----------------")

	// Sort changes by severity (most critical first)
	sortChangesBySeverity(changes)

	// Print each change
	for i, change := range changes {
		printChangeDetails(i+1, change)
	}
}

// sortChangesBySeverity sorts changes by their severity level
func sortChangesBySeverity(changes []*audit.Change) {
	sort.Slice(changes, func(i, j int) bool {
		// Define severity order
		severity := map[string]int{
			"modified_content":     0,
			"modified_owner":       1,
			"modified_permissions": 2,
			"deleted":              3,
			"added":                4,
		}
		return severity[changes[i].ChangeType] < severity[changes[j].ChangeType]
	})
}

// printChangeDetails prints detailed information about a specific change
func printChangeDetails(index int, change *audit.Change) {
	fmt.Printf("\n[%d] %s\n", index, formatChangeType(change.ChangeType))
	fmt.Printf("Path: %s\n", change.Binary.Path)
	fmt.Printf("Detected: %s\n", change.DetectedTime.Format("2006-01-02 15:04:05"))

	switch change.ChangeType {
	case "added":
		fmt.Printf("Owner: %s\n", change.Binary.Owner)
		fmt.Printf("Permissions: %s\n", change.Binary.Permissions)
		fmt.Printf("SHA256: %s\n", change.Binary.SHA256Hash)
	case "deleted":
		// Nothing additional for deleted binaries
	case "modified_content":
		fmt.Printf("Old Hash: %s\n", change.OldValue)
		fmt.Printf("New Hash: %s\n", change.NewValue)
	case "modified_permissions":
		fmt.Printf("Old Permissions: %s\n", change.OldValue)
		fmt.Printf("New Permissions: %s\n", change.NewValue)
	case "modified_owner":
		fmt.Printf("Old Owner: %s\n", change.OldValue)
		fmt.Printf("New Owner: %s\n", change.NewValue)
	}
}

// formatChangeType returns a human-readable change type
func formatChangeType(changeType string) string {
	switch changeType {
	case "added":
		return "Binary Added"
	case "deleted":
		return "Binary Deleted"
	case "modified_content":
		return "Content Modified"
	case "modified_permissions":
		return "Permissions Modified"
	case "modified_owner":
		return "Owner Modified"
	default:
		return changeType
	}
}

func init() {
	// Override the Run function with our implementation
	reportCmd.Run = func(cmd *cobra.Command, args []string) {
		if err := runReport(cmd, args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}
