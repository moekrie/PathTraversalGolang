package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// detectOS identifies the operating system
func detectOS() string {
	return runtime.GOOS
}

// detectLanguageVersions checks installed versions of common programming languages
func detectLanguageVersions() map[string]string {
	languages := map[string]string{
		"Go":      "go version",
		"Python":  "python --version",
		"Python3": "python3 --version",
		"Node.js": "node -v",
		"Ruby":    "ruby -v",
		"Java":    "java --version",
	}

	versions := make(map[string]string)

	for lang, cmd := range languages {
		output, err := exec.Command("sh", "-c", cmd).Output()
		if err == nil {
			versions[lang] = strings.TrimSpace(string(output))
		} else {
			versions[lang] = "Not Installed"
		}
	}
	return versions
}

// scanVulnerabilities mendeteksi pola berbahaya dalam file
func scanVulnerabilities(code string) []string {
	vulns := []string{}

	// Deteksi akses file tanpa validasi path
	if strings.Contains(code, "os.ReadFile(") {
		vulns = append(vulns, "[WARNING] Possible arbitrary file read vulnerability: `os.ReadFile(filePath)` detected.")
	}

	// Deteksi path traversal
	if strings.Contains(code, "../") || strings.Contains(code, "..\\") {
		vulns = append(vulns, "[WARNING] Possible path traversal attack detected: '../' or '..\\'.")
	}

	return vulns
}

// replaceVulnerabilities mengganti os.ReadFile(filePath) dengan metode aman
func replaceVulnerabilities(code string) string {
	replacements := map[string]string{
		"os.ReadFile(filePath)": `safePath := filepath.Clean(filePath)
if strings.Contains(safePath, "..") {
	http.Error(w, "Access denied", http.StatusForbidden)
	return
}
data, err := os.ReadFile(safePath)`,
		"../":  "safe_path/",
		"..\\": "safe_path\\",
	}

	modifiedCode := code
	report := []string{}

	for vuln, safe := range replacements {
		if strings.Contains(code, vuln) {
			fmt.Printf("\n [DETECTED] Vulnerable pattern found: `%s`\n", vuln)
			fmt.Printf("Location: Inside the scanned file\n")
			fmt.Printf("Suggested Fix: Replace with a safer version\n")
			fmt.Printf("\n Do you want to replace it? (y/n): ")

			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			response := strings.ToLower(scanner.Text())

			if response == "y" {
				modifiedCode = strings.ReplaceAll(modifiedCode, vuln, safe)
				report = append(report, fmt.Sprintf(" Replaced `%s` with safer code.", vuln))
			}
		}
	}

	fmt.Println("\n Replacement Report:")
	if len(report) > 0 {
		for _, r := range report {
			fmt.Println(r)
		}
	} else {
		fmt.Println("No replacements made.")
	}

	return modifiedCode
}

// readFile membaca file yang diberikan oleh pengguna
func readFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// writeFile menyimpan kode yang sudah diperbaiki ke file baru
func writeFile(filePath string, content string) error {
	newFilePath := strings.TrimSuffix(filePath, filepath.Ext(filePath)) + "_fixed" + filepath.Ext(filePath)
	err := os.WriteFile(newFilePath, []byte(content), 0644)
	if err != nil {
		return err
	}
	fmt.Println("\n Updated file saved as:", newFilePath)
	return nil
}

func main() {
	fmt.Println("Detecting OS...")
	fmt.Println("Operating System:", detectOS())

	fmt.Println("\nDetecting Installed Programming Language Versions...")
	versions := detectLanguageVersions()
	for lang, version := range versions {
		fmt.Printf("%s: %s\n", lang, version)
	}

	// Meminta pengguna memasukkan path file yang akan dipindai
	fmt.Print("\n Enter the path of the file to scan: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	filePath := scanner.Text()

	// Membaca file
	fmt.Println("\n Reading file:", filePath)
	code, err := readFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// Memindai file dari kerentanan
	fmt.Println("\nScanning for vulnerabilities...")
	vulns := scanVulnerabilities(code)
	if len(vulns) > 0 {
		for _, vuln := range vulns {
			fmt.Println(vuln)
		}
	} else {
		fmt.Println("No vulnerabilities found.")
	}

	// Memperbaiki file
	fmt.Println("\n Replacing vulnerabilities...")
	safeCode := replaceVulnerabilities(code)

	// Menyimpan file yang telah diperbaiki
	err = writeFile(filePath, safeCode)
	if err != nil {
		fmt.Println(" Error saving file:", err)
	}
}
