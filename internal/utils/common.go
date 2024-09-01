package utils

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

func IsValidDomain(str string) bool {
	parts := strings.Split(str, ".")

	domainRegex := regexp.MustCompile("^[a-zA-Z0-9][-a-zA-Z0-9]{0,252}[a-zA-Z0-9]$|^[a-zA-Z0-9]$")

	hasValidParts := true

	for _, part := range parts {
		hasValidParts = hasValidParts && domainRegex.MatchString(part)
	}

	return hasValidParts
}

func ReadFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false
	}
	return !info.IsDir()
}
