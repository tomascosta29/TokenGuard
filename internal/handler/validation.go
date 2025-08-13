package handler

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 128
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9]{3,20}$`)

// validateUsername checks if the provided username meets formatting requirements.
func validateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username must be 3-20 characters long and contain only letters and numbers")
	}
	return nil
}

// validatePasswordComplexity checks if a password meets complexity requirements.
func validatePasswordComplexity(password string) error {
	if len(password) < minPasswordLength || len(password) > maxPasswordLength {
		return fmt.Errorf("password must be between %d and %d characters long", minPasswordLength, maxPasswordLength)
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case isSpecialCharacter(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// isSpecialCharacter checks if a character is a special character.
// Using strings.ContainsRune for efficiency.
func isSpecialCharacter(char rune) bool {
	const specialChars = "!\"#$%&'()*+,-./:;<=>?@[]^_{|}~"
	return strings.ContainsRune(specialChars, char)
}
