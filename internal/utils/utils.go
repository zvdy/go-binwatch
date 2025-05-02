package utils

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zvdy/go-binwatch/pkg/config"
	"github.com/zvdy/go-binwatch/pkg/security"
)

// FormatDuration formats a time.Duration into a human-readable string
func FormatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	parts := []string{}

	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d days", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hours", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d minutes", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d seconds", seconds))
	}

	return strings.Join(parts, ", ")
}

// FormatBytes formats bytes into a human-readable string
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// CheckConfigSecurity verifies that the config file has proper security settings
func CheckConfigSecurity(configPath string, requiredUser string) error {
	// Check file exists
	_, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		return nil // File doesn't exist yet, that's okay
	} else if err != nil {
		return fmt.Errorf("failed to check config file: %w", err)
	}

	// Check permissions
	secure, err := security.CheckFilePermissions(configPath, 0640)
	if err != nil {
		return fmt.Errorf("failed to check config permissions: %w", err)
	}
	if !secure {
		return fmt.Errorf("config file has insecure permissions")
	}

	// Check ownership
	owned, err := security.CheckFileOwnership(configPath, requiredUser)
	if err != nil {
		return fmt.Errorf("failed to check config ownership: %w", err)
	}
	if !owned {
		return fmt.Errorf("config file not owned by %s", requiredUser)
	}

	return nil
}

// VerifyUserAccess checks if the current user has access to run the tool
func VerifyUserAccess(allowedUser string) error {
	// Root can always run the tool
	if security.CheckRoot() {
		return nil
	}

	// Check if we're the allowed user
	isAllowed, err := security.CheckUser(allowedUser)
	if err != nil {
		return fmt.Errorf("failed to check current user: %w", err)
	}
	if !isAllowed {
		return fmt.Errorf("access denied: only user '%s' or 'root' can run this tool", allowedUser)
	}

	return nil
}

// ValidateAndFixConfig validates config settings and fixes issues when possible
func ValidateAndFixConfig(cfg *config.Config) ([]string, error) {
	var warnings []string

	// Check if binwatch user exists
	if !security.CheckUserExists(cfg.BinwatchUser) {
		if security.CheckRoot() {
			// Create the user if we're root
			err := security.CreateUser(cfg.BinwatchUser)
			if err != nil {
				return warnings, fmt.Errorf("failed to create binwatch user: %w", err)
			}
			warnings = append(warnings, fmt.Sprintf("Created system user '%s'", cfg.BinwatchUser))
		} else {
			warnings = append(warnings, fmt.Sprintf("Binwatch user '%s' does not exist. Run as root to create it", cfg.BinwatchUser))
		}
	}

	// Create database directory with proper permissions if it doesn't exist
	dbDir := strings.TrimSuffix(cfg.DatabasePath, "/database.db")
	err := security.EnsureDirectory(dbDir, 0750, cfg.BinwatchUser)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Failed to create/secure database directory: %v", err))
	}

	// Create log directory with proper permissions if it doesn't exist
	logDir := strings.TrimSuffix(cfg.LogPath, "/audit.log")
	err = security.EnsureDirectory(logDir, 0750, cfg.BinwatchUser)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Failed to create/secure log directory: %v", err))
	}

	// Validate scan paths
	for i, path := range cfg.ScanPaths {
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("Scan path does not exist: %s", path))
			// Remove invalid path
			cfg.ScanPaths = append(cfg.ScanPaths[:i], cfg.ScanPaths[i+1:]...)
		}
	}

	// Ensure we have at least one scan path
	if len(cfg.ScanPaths) == 0 {
		cfg.ScanPaths = []string{"/bin", "/usr/bin"}
		warnings = append(warnings, "No valid scan paths, reset to default paths")
	}

	// Validate cron interval format (basic check)
	cronFields := strings.Fields(cfg.CronInterval)
	if len(cronFields) != 5 {
		cfg.CronInterval = "0 */6 * * *" // Every 6 hours
		warnings = append(warnings, "Invalid cron interval format, reset to '0 */6 * * *'")
	}

	return warnings, nil
}

// CreateSetupScript creates a setup script to be run as root
func CreateSetupScript(config *config.Config, scriptPath string) error {
	script := `#!/bin/bash
# BinWatch Setup Script
# This script sets up the BinWatch binary auditing tool

set -e

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Create binwatch user
if ! id -u "%s" &>/dev/null; then
    echo "Creating %s user..."
    useradd --system --shell /bin/false --no-create-home --comment "BinWatch Audit Tool" "%s"
fi

# Create directories
echo "Creating required directories..."
mkdir -p "%s" # Database directory
mkdir -p "%s" # Log directory

# Set permissions
echo "Setting secure permissions..."
chown -R "%s" "%s" "%s"
chmod 750 "%s" "%s"

# Install binwatch to /usr/local/bin
if [ -f "./binwatch" ]; then
    echo "Installing binwatch to /usr/local/bin..."
    mkdir -p /usr/local/bin
    install -o root -g root -m 755 ./binwatch /usr/local/bin/binwatch
    echo "Installed binwatch to /usr/local/bin/binwatch"
else
    echo "Warning: binwatch binary not found in current directory, skipping installation"
fi

# Create default configuration
CONFIG_DIR="/etc/binwatch"
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/binwatch.yaml" << EOL
database_path: %s
log_path: %s
scan_paths:
  - /bin
  - /usr/bin
  - /usr/local/bin
  - /sbin
  - /usr/sbin
whitelisted_bins: []
binwatch_user: %s
cron_interval: "%s"
enable_audit: true
EOL
chmod 640 "$CONFIG_DIR/binwatch.yaml"
chown root:%s "$CONFIG_DIR/binwatch.yaml"
echo "Created default configuration file at $CONFIG_DIR/binwatch.yaml"

echo ""
echo "BinWatch setup complete!"
echo "Run 'binwatch init' to initialize the database."
echo ""
echo "To manage the automatic scanning cronjob:"
echo "- Enable:  binwatch cron enable"
echo "- Disable: binwatch cron disable"
echo "- Status:  binwatch cron status"
`

	content := fmt.Sprintf(script,
		config.BinwatchUser, config.BinwatchUser, config.BinwatchUser,
		strings.TrimSuffix(config.DatabasePath, "/database.db"),
		strings.TrimSuffix(config.LogPath, "/audit.log"),
		config.BinwatchUser,
		strings.TrimSuffix(config.DatabasePath, "/database.db"),
		strings.TrimSuffix(config.LogPath, "/audit.log"),
		strings.TrimSuffix(config.DatabasePath, "/database.db"),
		strings.TrimSuffix(config.LogPath, "/audit.log"),
		config.DatabasePath,
		config.LogPath,
		config.BinwatchUser,
		config.CronInterval,
		config.BinwatchUser)

	return os.WriteFile(scriptPath, []byte(content), 0755)
}
