package notification

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/zvdy/go-binwatch/pkg/audit"
)

// Severity levels for notifications
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Notifier handles sending notifications about binary changes
type Notifier struct {
	MinSeverity string
}

// NewNotifier creates a new notifier with the specified minimum severity level
func NewNotifier(minSeverity string) *Notifier {
	// Default to medium if not specified
	if minSeverity == "" {
		minSeverity = SeverityMedium
	}

	return &Notifier{
		MinSeverity: strings.ToLower(minSeverity),
	}
}

// getSeverityLevel maps a change type to a severity level
func getSeverityLevel(change *audit.Change) string {
	switch change.ChangeType {
	case "added":
		return SeverityMedium
	case "deleted":
		return SeverityHigh
	case "modified_content":
		return SeverityCritical
	case "modified_permissions":
		return SeverityHigh
	case "modified_owner":
		return SeverityHigh
	default:
		return SeverityLow
	}
}

// shouldNotify determines if a notification should be sent based on severity
func (n *Notifier) shouldNotify(severity string) bool {
	severityMap := map[string]int{
		SeverityLow:      1,
		SeverityMedium:   2,
		SeverityHigh:     3,
		SeverityCritical: 4,
	}

	changeSev := severityMap[severity]
	minSev := severityMap[n.MinSeverity]

	return changeSev >= minSev
}

// getNotificationTitle generates a title for the notification
func getNotificationTitle(change *audit.Change) string {
	switch change.ChangeType {
	case "added":
		return fmt.Sprintf("New binary detected: %s", filepath.Base(change.Binary.Path))
	case "deleted":
		return fmt.Sprintf("Binary removed: %s", filepath.Base(change.Binary.Path))
	case "modified_content":
		return fmt.Sprintf("Binary content changed: %s", filepath.Base(change.Binary.Path))
	case "modified_permissions":
		return fmt.Sprintf("Binary permissions changed: %s", filepath.Base(change.Binary.Path))
	case "modified_owner":
		return fmt.Sprintf("Binary owner changed: %s", filepath.Base(change.Binary.Path))
	default:
		return fmt.Sprintf("Binary change detected: %s", filepath.Base(change.Binary.Path))
	}
}

// getNotificationMessage generates a detailed message for the notification
func getNotificationMessage(change *audit.Change) string {
	path := change.Binary.Path

	switch change.ChangeType {
	case "added":
		return fmt.Sprintf("New binary detected at %s\nSHA256: %s\nPermissions: %s\nOwner: %s",
			path, change.Binary.SHA256Hash, change.Binary.Permissions, change.Binary.Owner)
	case "deleted":
		return fmt.Sprintf("Binary at %s has been deleted", path)
	case "modified_content":
		return fmt.Sprintf("Binary content changed at %s\nOld hash: %s\nNew hash: %s",
			path, change.OldValue, change.NewValue)
	case "modified_permissions":
		return fmt.Sprintf("Binary permissions changed at %s\nOld: %s\nNew: %s",
			path, change.OldValue, change.NewValue)
	case "modified_owner":
		return fmt.Sprintf("Binary owner changed at %s\nOld: %s\nNew: %s",
			path, change.OldValue, change.NewValue)
	default:
		return fmt.Sprintf("Unspecified change detected for binary at %s", path)
	}
}

// SendDesktopNotification sends a desktop notification using notify-send
func (n *Notifier) SendDesktopNotification(change *audit.Change) error {
	severity := getSeverityLevel(change)

	if !n.shouldNotify(severity) {
		return nil // Skip notifications below threshold
	}

	title := getNotificationTitle(change)
	message := getNotificationMessage(change)

	// Use notify-send for desktop notifications
	urgency := "normal"
	if severity == SeverityCritical || severity == SeverityHigh {
		urgency = "critical"
	}

	// Try multiple notification methods in order of preference
	err := tryMultipleNotificationMethods(title, message, urgency)
	if err != nil {
		// On failure, write to a notification file as fallback
		fallbackFile := filepath.Join(os.TempDir(), "binwatch_notifications.txt")
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		notifText := fmt.Sprintf("[%s] %s - %s\n%s\n\n",
			timestamp, urgency, title, message)

		// Append to file (create if doesn't exist)
		f, err := os.OpenFile(fallbackFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			defer f.Close()
			f.WriteString(notifText)
			return fmt.Errorf("desktop notification failed, wrote to %s", fallbackFile)
		}
	}

	return err
}

// tryMultipleNotificationMethods attempts several methods to send notifications
func tryMultipleNotificationMethods(title, message, urgency string) error {
	var lastErr error

	// Get current user info
	isRoot := os.Geteuid() == 0
	var sudoUser string
	var actualUser string

	if isRoot {
		// Get the actual user who invoked sudo
		sudoUser = os.Getenv("SUDO_USER")
		if sudoUser != "" {
			actualUser = sudoUser
		}
	}

	// Method 1: Direct notify-send (works when not root)
	if !isRoot {
		cmd := exec.Command("notify-send",
			"--app-name=BinWatch",
			fmt.Sprintf("--urgency=%s", urgency),
			"--icon=security-high",
			title,
			message)

		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	// Method 2: When root, use sudo -u with proper env variables
	if isRoot && actualUser != "" {
		userInfo, err := user.Lookup(actualUser)
		if err == nil {
			// Path to user's XDG runtime directory
			xdgRunDir := fmt.Sprintf("/run/user/%s", userInfo.Uid)

			// Common D-Bus socket locations
			socketLocations := []string{
				fmt.Sprintf("unix:path=%s/bus", xdgRunDir),
				fmt.Sprintf("unix:path=%s/dbus-1/user_bus_socket", xdgRunDir),
			}

			// Try with specific socket path
			for _, socket := range socketLocations {
				cmd := exec.Command("sudo", "-u", actualUser, "env",
					fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=%s", socket),
					fmt.Sprintf("XDG_RUNTIME_DIR=%s", xdgRunDir),
					"DISPLAY=:0",
					"notify-send",
					"--app-name=BinWatch",
					fmt.Sprintf("--urgency=%s", urgency),
					"--icon=security-high",
					title,
					message)

				if err := cmd.Run(); err == nil {
					return nil
				} else {
					lastErr = err
				}
			}
		}
	}

	// Method 3: Try using systemd-run to run in user context
	if isRoot && actualUser != "" {
		cmd := exec.Command("systemd-run", "--user", "--on-active=1",
			"--uid="+actualUser,
			"notify-send",
			"--app-name=BinWatch",
			fmt.Sprintf("--urgency=%s", urgency),
			"--icon=security-high",
			title,
			message)

		if err := cmd.Run(); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}

	// Method 4: Try using wall command to broadcast to all terminals
	// This is a last resort for system-wide notification
	cmd := exec.Command("wall", fmt.Sprintf("BinWatch Alert: %s - %s", title, message))
	if err := cmd.Run(); err == nil {
		return nil
	} else {
		lastErr = err
	}

	return fmt.Errorf("all notification methods failed: %v", lastErr)
}

// NotifyChanges sends notifications for all detected changes
func (n *Notifier) NotifyChanges(changes []*audit.Change) {
	if len(changes) == 0 {
		return
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	// Send individual notifications for critical and high changes
	for _, change := range changes {
		severity := getSeverityLevel(change)

		switch severity {
		case SeverityCritical:
			criticalCount++
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			mediumCount++
		case SeverityLow:
			lowCount++
		}

		// Only send desktop notifications for high and critical changes to avoid spam
		if severity == SeverityCritical || severity == SeverityHigh {
			err := n.SendDesktopNotification(change)
			if err != nil {
				log.Printf("Notification issue: %v", err)
			}
		}
	}

	// Send summary notification if changes were detected
	totalChanges := len(changes)
	if totalChanges > 0 {
		title := fmt.Sprintf("BinWatch detected %d binary changes", totalChanges)
		message := fmt.Sprintf(
			"Critical: %d\nHigh: %d\nMedium: %d\nLow: %d\n\nRun 'binwatch report' to see details.",
			criticalCount, highCount, mediumCount, lowCount)

		urgency := "normal"
		if criticalCount > 0 || highCount > 0 {
			urgency = "critical"
		}

		err := tryMultipleNotificationMethods(title, message, urgency)
		if err != nil {
			log.Printf("Summary notification issue: %v", err)
		}
	}
}
