package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func cmdDecompile(args []string) error {
	fs := flag.NewFlagSet("decompile", flag.ExitOnError)
	inDir := fs.String("in", "", "input directory (disasm output)")
	libPath := fs.String("lib", "", "path to libapp.so (default: auto-detect from disasm)")
	projectDir := fs.String("projects", "scratch/ghidra-projects", "Ghidra project directory")
	ghidraHome := fs.String("ghidra-home", "", "Ghidra installation directory (auto-detected if omitted)")
	decompAll := fs.Bool("all", false, "decompile ALL functions (default: signal functions only)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		return fmt.Errorf("--in is required")
	}

	// 1. Find Ghidra.
	analyzeHeadless, ghHome, err := findGhidra(*ghidraHome)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "ghidra: %s\n", ghHome)

	// 2. Generate ghidra_meta.json (always regenerate to pick up --all).
	metaPath := filepath.Join(*inDir, "ghidra_meta.json")
	metaArgs := []string{"--in", *inDir, "--out", metaPath}
	if *decompAll {
		metaArgs = append(metaArgs, "--decompile-all")
	}
	fmt.Fprintf(os.Stderr, "generating ghidra_meta.json...\n")
	if err := cmdGhidraMeta(metaArgs); err != nil {
		return fmt.Errorf("ghidra-meta: %w", err)
	}

	// 3. Find libapp.so if not specified.
	if *libPath == "" {
		// Try common locations relative to --in.
		candidates := []string{
			filepath.Join(filepath.Dir(*inDir), "libapp.so"),
			filepath.Join(*inDir, "..", "libapp.so"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				abs, _ := filepath.Abs(c)
				*libPath = abs
				break
			}
		}
		if *libPath == "" {
			return fmt.Errorf("cannot find libapp.so; specify with --lib")
		}
	}
	fmt.Fprintf(os.Stderr, "libapp: %s\n", *libPath)

	// 4. Prepare output paths.
	decompDir := filepath.Join(*inDir, "decompiled")
	absMetaPath, _ := filepath.Abs(metaPath)
	absDecompDir, _ := filepath.Abs(decompDir)
	absLibPath, _ := filepath.Abs(*libPath)

	// Ghidra project name from the input directory.
	projectName := "unflutter_" + filepath.Base(filepath.Dir(*inDir))
	if projectName == "unflutter_." {
		projectName = "unflutter_decompile"
	}

	// 5. Create project directory.
	absProjDir, _ := filepath.Abs(*projectDir)
	if err := os.MkdirAll(absProjDir, 0o755); err != nil {
		return fmt.Errorf("create project dir: %w", err)
	}

	// 6. Get script path.
	scriptPath, err := findScriptPath()
	if err != nil {
		return err
	}

	// 7. Run analyzeHeadless.
	if *decompAll {
		fmt.Fprintf(os.Stderr, "running Ghidra headless analysis (decompiling ALL functions)...\n")
	} else {
		fmt.Fprintf(os.Stderr, "running Ghidra headless analysis (signal functions only, use --all for everything)...\n")
	}
	fmt.Fprintf(os.Stderr, "  project: %s/%s\n", absProjDir, projectName)
	fmt.Fprintf(os.Stderr, "  import: %s\n", absLibPath)
	fmt.Fprintf(os.Stderr, "  decompile output: %s\n", absDecompDir)

	ghidraArgs := []string{
		absProjDir,
		projectName,
		"-import", absLibPath,
		"-overwrite",
		"-scriptPath", scriptPath,
		"-preScript", "unflutter_prescript.py",
		"-postScript", "unflutter_apply.py", absMetaPath, absDecompDir,
	}

	// Set JAVA_HOME if not set (brew Ghidra needs it).
	env := os.Environ()
	if os.Getenv("JAVA_HOME") == "" {
		javaHome := findJavaHome(ghHome)
		if javaHome != "" {
			env = append(env, "JAVA_HOME="+javaHome)
		}
	}

	cmd := exec.Command(analyzeHeadless, ghidraArgs...)
	cmd.Env = env
	cmd.Stdout = os.Stderr // Ghidra output goes to stderr.
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("analyzeHeadless failed: %w", err)
	}

	// 8. Report results.
	entries, _ := os.ReadDir(absDecompDir)
	cCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".c") {
			cCount++
		}
	}
	fmt.Fprintf(os.Stderr, "decompiled %d functions → %s\n", cCount, absDecompDir)

	return nil
}

// findGhidra locates the Ghidra installation and analyzeHeadless binary.
// Search order:
//  1. --ghidra-home flag
//  2. GHIDRA_HOME environment variable
//  3. analyzeHeadless in PATH
//  4. ghidraRun in PATH → derive installation directory
//  5. Common brew paths
func findGhidra(explicitHome string) (analyzeHeadless string, ghidraHome string, err error) {
	// 1. Explicit --ghidra-home.
	if explicitHome != "" {
		ah := filepath.Join(explicitHome, "support", "analyzeHeadless")
		if _, err := os.Stat(ah); err == nil {
			return ah, explicitHome, nil
		}
		return "", "", fmt.Errorf("analyzeHeadless not found at %s/support/analyzeHeadless", explicitHome)
	}

	// 2. GHIDRA_HOME environment variable.
	if gh := os.Getenv("GHIDRA_HOME"); gh != "" {
		ah := filepath.Join(gh, "support", "analyzeHeadless")
		if _, err := os.Stat(ah); err == nil {
			return ah, gh, nil
		}
	}

	// 3. analyzeHeadless in PATH.
	if ah, err := exec.LookPath("analyzeHeadless"); err == nil {
		// Derive home: support/analyzeHeadless → parent/parent.
		home := filepath.Dir(filepath.Dir(ah))
		return ah, home, nil
	}

	// 4. ghidraRun in PATH → parse to find install dir.
	if gr, err := exec.LookPath("ghidraRun"); err == nil {
		home := deriveGhidraHome(gr)
		if home != "" {
			ah := filepath.Join(home, "support", "analyzeHeadless")
			if _, err := os.Stat(ah); err == nil {
				return ah, home, nil
			}
		}
	}

	// 5. Common brew Caskroom paths (Ghidra <12 with Jython support).
	caskPaths := []string{
		"/opt/homebrew/Caskroom/ghidra",
		"/usr/local/Caskroom/ghidra",
	}
	for _, cp := range caskPaths {
		if versions, err := os.ReadDir(cp); err == nil {
			for i := len(versions) - 1; i >= 0; i-- {
				v := versions[i]
				if !v.IsDir() {
					continue
				}
				// Caskroom layout: ghidra/<ver>/ghidra_<ver>_PUBLIC/support/analyzeHeadless
				subs, _ := os.ReadDir(filepath.Join(cp, v.Name()))
				for _, sub := range subs {
					if !sub.IsDir() {
						continue
					}
					ah := filepath.Join(cp, v.Name(), sub.Name(), "support", "analyzeHeadless")
					if _, err := os.Stat(ah); err == nil {
						return ah, filepath.Join(cp, v.Name(), sub.Name()), nil
					}
				}
			}
		}
	}

	// 6. Common brew Cellar paths (Ghidra 12+ — may need PyGhidra for Python scripts).
	cellarPaths := []string{
		"/opt/homebrew/Cellar/ghidra",
		"/usr/local/Cellar/ghidra",
	}
	for _, bp := range cellarPaths {
		if versions, err := os.ReadDir(bp); err == nil {
			for i := len(versions) - 1; i >= 0; i-- {
				v := versions[i]
				if !v.IsDir() {
					continue
				}
				ah := filepath.Join(bp, v.Name(), "libexec", "support", "analyzeHeadless")
				if _, err := os.Stat(ah); err == nil {
					return ah, filepath.Join(bp, v.Name(), "libexec"), nil
				}
			}
		}
	}

	return "", "", fmt.Errorf(`Ghidra not found

Install Ghidra:
  brew install ghidra

Or set GHIDRA_HOME:
  export GHIDRA_HOME=/path/to/ghidra

Or pass --ghidra-home:
  unflutter decompile --ghidra-home /path/to/ghidra --in <dir>`)
}

// deriveGhidraHome reads the ghidraRun shell script to find the real install path.
// Brew's ghidraRun wrapper contains: exec "/opt/homebrew/Cellar/ghidra/X.Y.Z/libexec/ghidraRun"
func deriveGhidraHome(ghidraRunPath string) string {
	data, err := os.ReadFile(ghidraRunPath)
	if err != nil {
		return ""
	}
	// Look for exec "..." pattern pointing to the real ghidraRun.
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// exec "/opt/homebrew/Cellar/ghidra/12.0.2/libexec/ghidraRun"
		if strings.Contains(line, "exec") && strings.Contains(line, "ghidraRun") {
			// Extract the quoted path.
			idx := strings.Index(line, `"`)
			if idx < 0 {
				continue
			}
			rest := line[idx+1:]
			end := strings.Index(rest, `"`)
			if end < 0 {
				continue
			}
			realPath := rest[:end]
			// ghidraRun is at <home>/ghidraRun, so home = dirname.
			home := filepath.Dir(realPath)
			if _, err := os.Stat(filepath.Join(home, "support")); err == nil {
				return home
			}
		}
	}
	return ""
}

// findScriptPath returns the path to the ghidra_scripts directory.
func findScriptPath() (string, error) {
	// Try relative to the binary.
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)

	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, ".unflutter", "ghidra_scripts"),
		filepath.Join(exeDir, "ghidra_scripts"),
		"ghidra_scripts",
		filepath.Join(exeDir, "..", "ghidra_scripts"),
	}

	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if _, err := os.Stat(filepath.Join(abs, "unflutter_apply.py")); err == nil {
			return abs, nil
		}
	}

	return "", fmt.Errorf("cannot find ghidra_scripts/unflutter_apply.py; run from the unflutter project root")
}

// findJavaHome tries to locate a suitable JDK for Ghidra.
func findJavaHome(ghidraHome string) string {
	// Check if the ghidraRun wrapper sets JAVA_HOME.
	gr := filepath.Join(ghidraHome, "ghidraRun")
	if data, err := os.ReadFile(gr); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "JAVA_HOME") && strings.Contains(line, ":-") {
				// JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/...}"
				idx := strings.Index(line, ":-")
				if idx >= 0 {
					rest := line[idx+2:]
					end := strings.IndexAny(rest, `}"`)
					if end > 0 {
						jh := rest[:end]
						if _, err := os.Stat(jh); err == nil {
							return jh
						}
					}
				}
			}
		}
	}

	// Common brew JDK paths.
	jdks := []string{
		"/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
		"/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
		"/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
	}
	for _, jh := range jdks {
		if _, err := os.Stat(jh); err == nil {
			return jh
		}
	}

	return ""
}
