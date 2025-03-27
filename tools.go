package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fatih/color"
)

// Inisialisasi warna
var (
	red    = color.New(color.FgRed).SprintFunc()      // Untuk kerentanan
	yellow = color.New(color.FgYellow).SprintFunc()   // Untuk peringatan
	green  = color.New(color.FgHiGreen).SprintFunc()  // Hijau neon untuk perbaikan dan kelulusan scan
	blue   = color.New(color.FgBlue).SprintFunc()     // Untuk informasi lainnya
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

	if strings.Contains(code, "os.ReadFile(") {
		vulns = append(vulns, yellow("[WARNING] ")+"Possible arbitrary file read vulnerability: "+red("`os.ReadFile(filePath)`")+" detected.")
	}

	if strings.Contains(code, "../") || strings.Contains(code, "..\\") {
		vulns = append(vulns, yellow("[WARNING] ")+"Possible path traversal attack detected: "+red("'../' or '..\\'")+".")
	}

	return vulns
}

// findLineNumber menemukan nomor baris pertama dari pola tertentu dalam kode
func findLineNumber(code, pattern string) int {
	lines := strings.Split(code, "\n")
	for i, line := range lines {
		if strings.Contains(line, pattern) {
			return i + 1
		}
	}
	return -1
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
	type replacementDetail struct {
		line    int
		before  string
		after   string
	}
	var report []replacementDetail

	for vuln, safe := range replacements {
		if strings.Contains(code, vuln) {
			lineNum := findLineNumber(code, vuln)
			fmt.Printf("\n %s Vulnerable pattern found: %s\n", red("[DETECTED]"), red("`"+vuln+"`"))
			fmt.Printf("%s Line %d\n", blue("Location:"), lineNum)
			fmt.Printf("%s Replace with a safer version\n", blue("Suggested Fix:"))
			fmt.Printf("\n %s ", blue("Do you want to replace it? (y/n):"))

			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			response := strings.ToLower(scanner.Text())

			if response == "y" {
				modifiedCode = strings.ReplaceAll(modifiedCode, vuln, safe)
				report = append(report, replacementDetail{
					line:   lineNum,
					before: vuln,
					after:  safe,
				})
			}
		}
	}

	fmt.Println("\n" + blue(" Replacement Report:"))
	if len(report) > 0 {
		for i, r := range report {
			fmt.Printf(" %s %d:\n", blue("Replacement"), i+1)
			fmt.Printf("   %s %s (Line %d)\n", red("Before Replacement:"), red("`"+r.before+"`"), r.line)
			fmt.Printf("   %s %s\n", green("After Replacement:"), green("`"+r.after+"`"))
		}
	} else {
		fmt.Println(green("No replacements made."))
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

// writeFile menyimpan kode yang sudah diperbaiki ke file asli
func writeFile(filePath string, content string) error {
	err := os.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		return err
	}
	fmt.Printf("\n %s %s\n", green("File has been updated at:"), filePath)
	return nil
}

func main() {
	fmt.Println(blue("Detecting OS..."))
	fmt.Printf("%s %s\n", blue("Operating System:"), detectOS())

	fmt.Println(blue("\nDetecting Installed Programming Language Versions..."))
	versions := detectLanguageVersions()
	for lang, version := range versions {
		fmt.Printf("%s: %s\n", blue(lang), version)
	}

	fmt.Print(blue("\n Enter the path of the file to scan: "))
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	filePath := scanner.Text()

	fmt.Printf("\n %s %s\n", blue("Reading file:"), filePath)
	code, err := readFile(filePath)
	if err != nil {
		fmt.Printf("%s %s\n", red("Error reading file:"), err)
		return
	}

	fmt.Println(blue("\nScanning for vulnerabilities..."))
	vulns := scanVulnerabilities(code)
	if len(vulns) > 0 {
		for _, vuln := range vulns {
			fmt.Println(vuln)
		}
	} else {
		fmt.Println(green("No vulnerabilities found."))
	}

	fmt.Println(blue("\n Replacing vulnerabilities..."))
	safeCode := replaceVulnerabilities(code)

	err = writeFile(filePath, safeCode)
	if err != nil {
		fmt.Printf("%s %s\n", red("Error saving file:"), err)
	}
}
