package security

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// CheckRoot returns whether the current process is running as root
func CheckRoot() bool {
	return os.Geteuid() == 0
}

// CheckUser verifies if the current user is the specified user
func CheckUser(username string) (bool, error) {
	currentUser, err := user.Current()
	if err != nil {
		return false, fmt.Errorf("failed to get current user: %w", err)
	}

	return currentUser.Username == username, nil
}

// CheckFilePermissions checks if a file has secure permissions
func CheckFilePermissions(path string, maxPermissions os.FileMode) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	mode := info.Mode().Perm()
	return mode&^maxPermissions == 0, nil
}

// CheckFileOwnership checks if a file is owned by the specified user
func CheckFileOwnership(path string, ownerUsername string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("failed to get file ownership info")
	}

	usr, err := user.Lookup(ownerUsername)
	if err != nil {
		return false, err
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return false, err
	}

	return int(stat.Uid) == uid, nil
}

// SetPermissions sets secure permissions on a file
func SetPermissions(path string, perm os.FileMode) error {
	return os.Chmod(path, perm)
}

// SetOwnership sets ownership on a file
func SetOwnership(path string, username string) error {
	usr, err := user.Lookup(username)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return err
	}

	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return err
	}

	return os.Chown(path, uid, gid)
}

// CheckUserExists checks if a user exists in the system
func CheckUserExists(username string) bool {
	_, err := user.Lookup(username)
	return err == nil
}

// CreateUser creates a system user for binwatch if it doesn't exist
func CreateUser(username string) error {
	if CheckUserExists(username) {
		return nil
	}

	// Only root can create users
	if !CheckRoot() {
		return fmt.Errorf("must be root to create user %s", username)
	}

	// Create system user
	cmd := exec.Command("useradd",
		"--system",              // System account
		"--shell", "/bin/false", // No login shell
		"--no-create-home",                 // No home directory
		"--comment", "BinWatch Audit Tool", // Comment
		username)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create user %s: %w", username, err)
	}

	return nil
}

// EnsureDirectory creates a directory with proper permissions and ownership
func EnsureDirectory(path string, perm os.FileMode, owner string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}

	// Set proper ownership if owner is specified
	if owner != "" {
		if err := SetOwnership(path, owner); err != nil {
			return fmt.Errorf("failed to set ownership on %s: %w", path, err)
		}
	}

	// Ensure permissions are correct
	if err := SetPermissions(path, perm); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}

	return nil
}

// SecureFile sets secure permissions and ownership on a file
func SecureFile(path string, perm os.FileMode, owner string) error {
	// Set ownership if owner is specified
	if owner != "" {
		if err := SetOwnership(path, owner); err != nil {
			return fmt.Errorf("failed to set ownership on %s: %w", path, err)
		}
	}

	// Set permissions
	if err := SetPermissions(path, perm); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", path, err)
	}

	return nil
}

// DropPrivileges attempts to drop root privileges to the specified user
// Note: This is generally difficult to do properly in Go, and is usually
// better handled by running the program as the correct user from the start
func DropPrivileges(username string) error {
	// Only try to drop privileges if we're root
	if !CheckRoot() {
		return nil
	}

	// Look up the user
	usr, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("failed to look up user %s: %w", username, err)
	}

	// Parse uid/gid
	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return fmt.Errorf("invalid uid: %w", err)
	}

	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return fmt.Errorf("invalid gid: %w", err)
	}

	// Set groups
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("failed to set groups: %w", err)
	}

	// Set GID
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("failed to set gid: %w", err)
	}

	// Set UID
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("failed to set uid: %w", err)
	}

	return nil
}
