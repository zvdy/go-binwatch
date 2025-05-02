package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config holds the global configuration for BinWatch
type Config struct {
	DatabasePath    string   `yaml:"database_path"`
	LogPath         string   `yaml:"log_path"`
	ScanPaths       []string `yaml:"scan_paths"`
	WhitelistedBins []string `yaml:"whitelisted_bins"`
	BinwatchUser    string   `yaml:"binwatch_user"`
	CronInterval    string   `yaml:"cron_interval"`
	EnableAudit     bool     `yaml:"enable_audit"`
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	// Using default paths without homeDir as we're using system paths
	return &Config{
		DatabasePath:    "/var/lib/binwatch/database.db",
		LogPath:         "/var/log/binwatch/audit.log",
		ScanPaths:       []string{"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"},
		WhitelistedBins: []string{},
		BinwatchUser:    "binwatch",
		CronInterval:    "0 */6 * * *", // Every 6 hours
		EnableAudit:     true,
	}
}

// LoadConfig loads configuration from file and environment
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Set up viper
	viper.SetConfigName("binwatch")
	viper.SetConfigType("yaml")

	// Check if config path is provided, otherwise use default locations
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.AddConfigPath("/etc/binwatch")
		viper.AddConfigPath("$HOME/.config/binwatch")
		viper.AddConfigPath(".")
	}

	// Environment variables
	viper.SetEnvPrefix("BINWATCH")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Try to read the config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, using defaults
	} else {
		// Unmarshal config
		if err := viper.Unmarshal(config); err != nil {
			return nil, fmt.Errorf("unable to decode config: %w", err)
		}
	}

	return config, nil
}

// SaveConfig saves the configuration to the specified file
func SaveConfig(config *Config, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal config to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}

	// Write file
	err = os.WriteFile(path, data, 0640)
	if err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}

// EnsureConfigSecurity verifies that config files and directories have proper permissions
func EnsureConfigSecurity(configPath string, requiredUser string) error {
	// Get required user info
	u, err := user.Lookup(requiredUser)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", requiredUser, err)
	}

	// Check file permissions and ownership
	info, err := os.Stat(configPath)
	if err == nil {
		// File exists, check permissions
		perm := info.Mode().Perm()
		if perm&0077 != 0 {
			return fmt.Errorf("config file has too permissive permissions: %v", perm)
		}

		// Check ownership
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to get file owner info")
		}

		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("invalid uid: %w", err)
		}

		if int(stat.Uid) != uid {
			return fmt.Errorf("config file not owned by %s", requiredUser)
		}
	}

	return nil
}

// ValidateUserAccess checks if the current user is the allowed binwatch user
func ValidateUserAccess(allowedUser string) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Allow root to run the tool as well
	if currentUser.Username == "root" {
		return nil
	}

	if currentUser.Username != allowedUser {
		return fmt.Errorf("access denied: only user '%s' or 'root' can run this tool", allowedUser)
	}

	return nil
}
