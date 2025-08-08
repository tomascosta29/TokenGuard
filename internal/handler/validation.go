package handler

import (
	"fmt"
	"regexp"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9]{3,20}$`)

// validateUsername checks if the provided username meets formatting requirements.
func validateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("Invalid username format")
	}
	return nil
}
