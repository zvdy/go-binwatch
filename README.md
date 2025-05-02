# BinWatch - Secure Linux Binary Auditing Tool

[![Go Report Card](https://goreportcard.com/badge/github.com/zvdy/go-binwatch)](https://goreportcard.com/report/github.com/zvdy/go-binwatch)

<div align="center">
    <img src="https://i.imgur.com/GyCGhoZ.png" alt="BinWatch Logo" width="160">  
    <p><em>BinWatch - Protecting your system one binary at a time.</em></p>
</div>

BinWatch is a secure command-line tool for Linux that monitors system binaries for changes and provides logging when modifications are detected. It's designed to be run as a cronjob or manually to provide a comprehensive auditing solution for system administrators concerned about security.

## Features

- **Binary Change Detection**: 
  - Monitors executable files for changes in content, permissions, or ownership
  - Supports multiple hash algorithms (SHA256, SHA512) for integrity verification
  - Fast and efficient scanning algorithms minimize system impact

- **Secure Logging**: 
  - Maintains an immutable log of all changes for forensic purposes
  - Logs are protected with secure permissions and user ownership
  - Structured log format allows easy analysis and filtering

- **Binary Whitelisting**: 
  - Exclude specific files or paths from monitoring
  - Support for glob patterns in whitelist entries
  - Configurable through both CLI and config file

- **Configurable Scanning**: 
  - Customize which directories to monitor
  - Set custom scan intervals
  - Control scan depth and verbosity

- **Security-First Design**: 
  - Implements proper permission controls and security measures
  - Dedicated system user with minimal privileges
  - Secure database and log storage

- **Detailed Reporting**: 
  - Generate comprehensive reports of changes over time
  - Filter reports by date range, change type, and severity
  - Output in human-readable or JSON format

- **Flexible Automation**: 
  - Control when and how scans run with cronjob management
  - Simple enable/disable commands
  - View current automation status

## Installation

### Prerequisites

- Linux system (tested on Debian/Ubuntu)
- Go 1.18 or higher (for building)
- Root access (for setup)

### Building from Source

1. Clone the repository:
   ```sh
   git clone https://github.com/zvdy/go-binwatch
   cd go-binwatch
   ```

2. Build the binary:
   ```sh
   go build -o binwatch ./cmd/binwatch
   ```

3. Run the setup script:
   ```sh
   sudo ./binwatch setup
   ```

4. Follow the prompts and then run:
   ```sh
   sudo bash /tmp/binwatch_setup.sh
   ```

5. Initialize the database:
   ```sh
   sudo binwatch init
   ```

### Binary Installation

Pre-built binaries are available on the [releases page](https://github.com/zvdy/go-binwatch/releases).

```sh
# Download the binary for your architecture
curl -L -o binwatch https://github.com/zvdy/go-binwatch/releases/download/v1.0.0/binwatch-linux-amd64

# Make it executable
chmod +x binwatch

# Run setup
sudo ./binwatch setup
```

## Usage

### Basic Commands

- **Initialize database**:
  ```sh
  sudo binwatch init
  ```
  Creates a new database with the current state of all binaries in the system. Use this for first-time setup or when you want to reset the baseline.

- **Scan for changes**:
  ```sh
  sudo binwatch scan
  ```
  Checks all monitored binaries against the database and logs any changes. Use the `--update` flag to update the database with the current state.

- **Generate a report**:
  ```sh
  sudo binwatch report
  ```
  Shows a detailed report of binary changes. Can filter by date, path, or change type.
  
  Options:
  ```
  --since <time>     Show changes since specified time (e.g. "24h", "7d", "2023-01-01")
  --path <pattern>   Filter by path (supports glob patterns)
  --type <type>      Filter by change type (added, removed, modified_content, modified_permissions, modified_owner)
  --critical         Show only critical changes (content modifications)
  ```

- **Manage whitelist**:
  ```sh
  sudo binwatch whitelist list                # List all whitelisted paths
  sudo binwatch whitelist add /path/to/binary # Add a path to the whitelist
  sudo binwatch whitelist remove /path/to/binary # Remove a path from the whitelist
  ```
  Manage which binaries are excluded from scanning. Useful for frequently changing binaries that are expected to change.

- **Manage cronjob**:
  ```sh
  sudo binwatch cron enable    # Enable automatic scanning
  sudo binwatch cron disable   # Disable automatic scanning
  sudo binwatch cron status    # Check current status
  ```
  Control the automated scanning schedule. When enabled, BinWatch will scan according to the defined interval.

### Configuration

BinWatch looks for configuration in the following locations (in order):
1. Custom path specified with `--config`
2. `/etc/binwatch/binwatch.yaml`
3. `$HOME/.config/binwatch/binwatch.yaml`

Configuration file example:
```yaml
# Database configuration
database_path: /var/lib/binwatch/database.db

# Logging configuration
log_path: /var/log/binwatch/audit.log

# Paths to monitor for binary changes
scan_paths:
  - /bin
  - /usr/bin
  - /usr/local/bin
  - /sbin
  - /usr/sbin

# Binaries to exclude from monitoring
whitelisted_bins:
  - /usr/bin/apt
  - /usr/bin/pip
  - /usr/bin/npm

# User that BinWatch will run as for privilege separation
binwatch_user: binwatch

# Cron schedule for automated scanning (crontab format)
cron_interval: "0 */6 * * *"  # Every 6 hours

# Whether to log to the system audit log
enable_audit: true
```

### Running as a Cron Job

BinWatch can be set up to run periodically for automated monitoring:

```sh
# Enable the cronjob (runs according to cron_interval in config)
sudo binwatch cron enable

# Check status
sudo binwatch cron status

# Disable the cronjob
sudo binwatch cron disable
```

By default, when enabled, the cronjob runs every 6 hours, but this can be customized in the configuration file.

## Security Considerations

- **Dedicated User**: BinWatch creates a system user (`binwatch`) with minimal privileges
- **Secure Logging**: Log files are secured with appropriate permissions
- **Protected Database**: The binary database is protected from unauthorized access
- **Audit Trail**: BinWatch automatically logs all activities for audit purposes
- **Immutable Records**: Change records cannot be modified once created

### Best Practices

1. **Regular Updates**: Keep BinWatch updated to the latest version
2. **Review Reports**: Regularly review scan reports, not just when alerts occur
3. **Proper Whitelisting**: Only whitelist binaries that are expected to change
4. **Secure Configuration**: Keep the configuration file properly secured
5. **Monitor the Monitor**: Consider monitoring the BinWatch binary and database with a separate tool

## Command Line Reference

```
Usage:
  binwatch [command] [flags]

Available Commands:
  help        Help about any command
  init        Initialize the binary database
  report      Generate a report of binary changes
  scan        Scan system binaries for changes
  setup       Set up BinWatch on the system
  whitelist   Manage binary whitelist
  cron        Manage the BinWatch cronjob

Global Flags:
  -c, --config string   config file path (default is /etc/binwatch/binwatch.yaml)
  -h, --help            help for binwatch
  -j, --json            output in JSON format
  -q, --quiet           quiet mode (minimal output)
  -v, --verbose         verbose mode (detailed output)
```

## Troubleshooting

### Common Issues

- **Permission denied errors**: Make sure you're running BinWatch with sudo or as root
- **Database not found**: Run `binwatch init` to create the initial database
- **Cronjob not running**: Verify the cron status with `binwatch cron status`
- **Too many changes reported**: Consider updating your whitelist to exclude frequently changing binaries

### Logs

BinWatch logs to `/var/log/binwatch/audit.log` by default. Check this file for detailed information about scans and errors.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgements

BinWatch relies on several excellent open-source libraries:

- [Cobra](https://github.com/spf13/cobra) - A powerful library for creating modern CLI applications
- [Viper](https://github.com/spf13/viper) - Complete configuration solution for Go applications
- [Afero](https://github.com/spf13/afero) - A filesystem abstraction system for Go
- [yaml.v3](https://github.com/go-yaml/yaml) - YAML support for Go
- [fsnotify](https://github.com/fsnotify/fsnotify) - Cross-platform file system notifications
- [go-toml](https://github.com/pelletier/go-toml) - TOML parser and encoder for Go
- [gotenv](https://github.com/subosito/gotenv) - Go library for loading environment variables
- [atomic](https://pkg.go.dev/go.uber.org/atomic) - Atomic primitives for Go
- [multierr](https://pkg.go.dev/go.uber.org/multierr) - Error handling primitives for Go
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - Supplementary Go cryptographic libraries
- [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) - Go packages for interacting with the operating system
