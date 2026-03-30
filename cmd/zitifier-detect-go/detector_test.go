package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/openziti/zitifier-detect-go/analyzer"
)

// buildBinary compiles the binary into a temp dir and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "zitifier-detect-go")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// Build from the module root (two levels up from this file).
	_, thisFile, _, _ := runtime.Caller(0)
	moduleRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	cmd := exec.Command("go", "build", "-o", bin, "./cmd/zitifier-detect-go/")
	cmd.Dir = moduleRoot
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build binary: %v", err)
	}
	return bin
}

func runDetector(t *testing.T, bin, root, minConf string, extraArgs ...string) analyzer.Report {
	t.Helper()
	args := []string{"-root", root, "-format", "json", "-min-confidence", minConf}
	args = append(args, extraArgs...)
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		t.Fatalf("detector failed: %v\nstdout: %s", err, out)
	}
	var report analyzer.Report
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("failed to parse JSON output: %v\noutput: %s", err, out)
	}
	return report
}

// testdataDir returns the absolute path to the testdata directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata")
}

func TestDetectsTCPDial(t *testing.T) {
	bin := buildBinary(t)
	td := testdataDir(t)
	root := filepath.Dir(td)

	report := runDetector(t, bin, root, "LOW", "testdata/simple_client.go")

	found := false
	for _, c := range report.Candidates {
		if c.Pattern == "net.Dial" {
			found = true
			if c.Type != "CLIENT" {
				t.Errorf("net.Dial should be CLIENT, got %s", c.Type)
			}
			break
		}
	}
	if !found {
		t.Error("expected net.Dial candidate, not found")
	}
}

func TestSkipsUnixSocket(t *testing.T) {
	bin := buildBinary(t)
	td := testdataDir(t)
	root := filepath.Dir(td)

	report := runDetector(t, bin, root, "LOW", "testdata/simple_client.go")

	// unix socket must appear in skipped, not candidates.
	for _, c := range report.Candidates {
		if c.Pattern == "net.Dial" && c.Confidence != "" {
			// check it's the tcp one, not unix
		}
	}
	unixSkipped := false
	for _, s := range report.Skipped {
		if s.Pattern == "net.Dial" {
			unixSkipped = true
		}
	}
	if !unixSkipped {
		t.Error("expected unix socket net.Dial in skipped list")
	}
}

func TestExternalURLIsLow(t *testing.T) {
	bin := buildBinary(t)
	td := testdataDir(t)
	root := filepath.Dir(td)

	report := runDetector(t, bin, root, "LOW", "-include-external", "testdata/external_url.go")

	found := false
	for _, c := range report.Candidates {
		if c.URLHint == "external" {
			found = true
			if c.Confidence != "LOW" {
				t.Errorf("external URL %s:%d should be LOW confidence, got %s", c.File, c.Line, c.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected at least one external URL candidate with -include-external")
	}
}

func TestLocalhostURLIsLow(t *testing.T) {
	bin := buildBinary(t)
	td := testdataDir(t)
	root := filepath.Dir(td)

	report := runDetector(t, bin, root, "LOW", "testdata/localhost.go")

	found := false
	for _, c := range report.Candidates {
		if c.URLHint == "localhost" {
			found = true
			if c.Confidence != "LOW" {
				t.Errorf("localhost URL %s:%d should be LOW, got %s", c.File, c.Line, c.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected at least one localhost URL candidate")
	}
}

func TestSkipsTestFiles(t *testing.T) {
	bin := buildBinary(t)
	td := testdataDir(t)
	root := filepath.Dir(td)

	report := runDetector(t, bin, root, "LOW", "testdata/test_file_test.go")

	if len(report.Candidates) != 0 {
		t.Errorf("expected 0 candidates from _test.go file, got %d", len(report.Candidates))
		for _, c := range report.Candidates {
			t.Logf("  unexpected: %s:%d %s", c.File, c.Line, c.Pattern)
		}
	}
}

func TestDetectsHTTPServer(t *testing.T) {
	bin := buildBinary(t)
	td := testdataDir(t)
	root := filepath.Dir(td)

	report := runDetector(t, bin, root, "HIGH", "testdata/server_listen.go")

	serverCount := 0
	for _, c := range report.Candidates {
		if c.Type == "SERVER" {
			serverCount++
		}
	}
	if serverCount < 3 {
		t.Errorf("expected ≥3 SERVER candidates, got %d", serverCount)
		for _, c := range report.Candidates {
			t.Logf("  %s:%d %s %s", c.File, c.Line, c.Type, c.Pattern)
		}
	}
}

func TestOutputSchemaShape(t *testing.T) {
	bin := buildBinary(t)
	td := testdataDir(t)
	root := filepath.Dir(td)

	report := runDetector(t, bin, root, "LOW", "-include-external", "./testdata")

	if report.SchemaVersion != "1" {
		t.Errorf("schema_version: want 1, got %q", report.SchemaVersion)
	}
	if report.Tool != "zitifier-detect-go" {
		t.Errorf("tool: want zitifier-detect-go, got %q", report.Tool)
	}
	if report.Summary.FilesAnalyzed == 0 {
		t.Error("files_analyzed should be > 0")
	}
	computed := report.Summary.Client + report.Summary.Server + report.Summary.Ambiguous
	if computed != report.Summary.TotalCandidates {
		t.Errorf("summary counts mismatch: %d+%d+%d=%d != total_candidates=%d",
			report.Summary.Client, report.Summary.Server, report.Summary.Ambiguous,
			computed, report.Summary.TotalCandidates)
	}
}
