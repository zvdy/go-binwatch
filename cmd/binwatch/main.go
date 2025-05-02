package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/zvdy/go-binwatch/internal/utils"
	"github.com/zvdy/go-binwatch/pkg/config"
)

var (
	configPath  string
	quietMode   bool
	verboseMode bool
	jsonOutput  bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "binwatch",
	Short: "A secure binary auditing tool for Linux systems",
	Long: `BinWatch - Linux Binary Auditing Tool
	
A secure tool for monitoring changes in system binaries.
It can be run as a cronjob or manually to audit binary files
and report any changes that might indicate security issues.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Skip validation for setup command
		if cmd.Name() == "setup" || cmd.Name() == "cron" {
			return
		}

		// Load config
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		// Verify user access
		if err := utils.VerifyUserAccess(cfg.BinwatchUser); err != nil {
			fmt.Fprintf(os.Stderr, "Access error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "config file path (default is /etc/binwatch/binwatch.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&quietMode, "quiet", "q", false, "quiet mode (minimal output)")
	rootCmd.PersistentFlags().BoolVarP(&verboseMode, "verbose", "v", false, "verbose mode (detailed output)")
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "output in JSON format")

	// Add commands
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(whitelistCmd)
	rootCmd.AddCommand(cronCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// cronCmd manages the cronjob for automatic scanning
var cronCmd = &cobra.Command{
	Use:   "cron [enable|disable|status]",
	Short: "Manage the BinWatch cronjob",
	Long:  `Enable, disable, or check the status of the BinWatch automatic scanning cronjob.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Error: Subcommand required (enable, disable, or status)")
			cmd.Help()
			os.Exit(1)
		}

		// Root required for cron management
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "Error: Root privileges required to manage cronjob")
			os.Exit(1)
		}

		cronFile := "/etc/cron.d/binwatch"
		action := args[0]

		switch action {
		case "enable":
			// Check if config file exists
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
				os.Exit(1)
			}

			// Create cron directory if it doesn't exist
			cronDir := filepath.Dir(cronFile)
			if err := os.MkdirAll(cronDir, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Error creating cron directory: %v\n", err)
				os.Exit(1)
			}

			// Write cron file
			cronContent := fmt.Sprintf("# BinWatch scheduled system binary audit\n%s root /usr/local/bin/binwatch scan --quiet\n",
				cfg.CronInterval)
			if err := os.WriteFile(cronFile, []byte(cronContent), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing cron file: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("BinWatch cronjob enabled")

		case "disable":
			// Check if cron file exists before trying to remove it
			if _, err := os.Stat(cronFile); os.IsNotExist(err) {
				fmt.Println("BinWatch cronjob already disabled")
				return
			}

			// Remove cron file
			if err := os.Remove(cronFile); err != nil {
				fmt.Fprintf(os.Stderr, "Error removing cron file: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("BinWatch cronjob disabled")

		case "status":
			// Check if cron file exists
			if _, err := os.Stat(cronFile); os.IsNotExist(err) {
				fmt.Println("BinWatch cronjob: Disabled")
				return
			}

			// Read and display cron content
			content, err := os.ReadFile(cronFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading cron file: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("BinWatch cronjob: Enabled")
			fmt.Println("Configuration:")
			fmt.Println(string(content))

		default:
			fmt.Fprintf(os.Stderr, "Error: Unknown subcommand %s\n", action)
			cmd.Help()
			os.Exit(1)
		}
	},
}

// setupCmd represents the setup command
var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up BinWatch on the system",
	Long:  `Sets up BinWatch on the system by creating required users, directories, and permissions.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load or create default config
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			cfg = config.DefaultConfig()
		}

		// Create setup script
		scriptPath := filepath.Join(os.TempDir(), "binwatch_setup.sh")
		if err := utils.CreateSetupScript(cfg, scriptPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating setup script: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Setup script created at %s\n", scriptPath)
		fmt.Println("Run the script as root to set up BinWatch:")
		fmt.Printf("sudo bash %s\n", scriptPath)

		// If we're already root, offer to run the script
		if os.Geteuid() == 0 {
			fmt.Print("You are running as root. Run setup script now? [y/N] ")
			var answer string
			fmt.Scanln(&answer)
			if answer == "y" || answer == "Y" {
				fmt.Println("Running setup script...")

				// Execute the script directly instead of just printing it
				cmd := exec.Command("bash", scriptPath)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Stdin = os.Stdin

				if err := cmd.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "Error running setup script: %v\n", err)
					os.Exit(1)
				}

				fmt.Println("\nSetup completed successfully.")
				fmt.Println("You can now initialize the database with: binwatch init")
			}
		}
	},
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan system binaries for changes",
	Long:  `Scan system binaries and compare with previous state to detect any changes.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Scanning system binaries...")
		// Implementation will be added in scan.go
	},
}

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the binary database",
	Long:  `Initialize or reset the binary database with current system state.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Initializing binary database...")
		// Implementation will be added in init.go
	},
}

// reportCmd represents the report command
var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report of binary changes",
	Long:  `Generate a detailed report of binary changes detected in the last scan.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Generating report...")
		// Implementation will be added in report.go
	},
}

// whitelistCmd represents the whitelist command
var whitelistCmd = &cobra.Command{
	Use:   "whitelist [add|remove|list] [path]",
	Short: "Manage binary whitelist",
	Long:  `Add, remove, or list whitelisted binaries that should be excluded from scanning.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Error: Subcommand required (add, remove, or list)")
			cmd.Help()
			os.Exit(1)
		}

		action := args[0]
		switch action {
		case "add":
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "Error: Path argument required")
				os.Exit(1)
			}
			fmt.Printf("Adding %s to whitelist...\n", args[1])
			// Implementation will be added in whitelist.go
		case "remove":
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "Error: Path argument required")
				os.Exit(1)
			}
			fmt.Printf("Removing %s from whitelist...\n", args[1])
			// Implementation will be added in whitelist.go
		case "list":
			fmt.Println("Listing whitelisted paths...")
			// Implementation will be added in whitelist.go
		default:
			fmt.Fprintf(os.Stderr, "Error: Unknown subcommand %s\n", action)
			cmd.Help()
			os.Exit(1)
		}
	},
}
