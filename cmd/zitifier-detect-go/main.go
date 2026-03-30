package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/openziti/zitifier-detect-go/analyzer"
	"golang.org/x/tools/go/ast/inspector"
	"golang.org/x/tools/go/packages"
)

func main() {
	var (
		root         = flag.String("root", ".", "Root directory of the Go module to analyze")
		outFile      = flag.String("out", "", "Output file path (default: stdout)")
		format       = flag.String("format", "json", "Output format: json or text")
		minConf      = flag.String("min-confidence", "MEDIUM", "Minimum confidence to report: HIGH, MEDIUM, LOW")
		inclExternal = flag.Bool("include-external", false, "Include LOW-confidence external URL candidates")
		verbose      = flag.Bool("v", false, "Print package loading progress to stderr")
	)
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot resolve root path: %v\n", err)
		os.Exit(1)
	}

	if *format != "json" && *format != "text" {
		fmt.Fprintf(os.Stderr, "ERROR: -format must be 'json' or 'text'\n")
		os.Exit(1)
	}

	confOrder := map[string]int{"LOW": 0, "MEDIUM": 1, "HIGH": 2}
	minLevel, ok := confOrder[strings.ToUpper(*minConf)]
	if !ok {
		fmt.Fprintf(os.Stderr, "ERROR: -min-confidence must be HIGH, MEDIUM, or LOW\n")
		os.Exit(1)
	}

	// ------------------------------------------------------------------ load
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedSyntax |
			packages.NeedModule,
		Dir:   absRoot,
		Tests: false,
	}

	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "Loading packages from %s ...\n", absRoot)
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: packages.Load: %v\n", err)
		os.Exit(1)
	}

	// Count unique source files.
	fileSet := map[string]struct{}{}
	for _, pkg := range pkgs {
		for _, f := range pkg.GoFiles {
			fileSet[f] = struct{}{}
		}
		if *verbose && len(pkg.Errors) > 0 {
			for _, e := range pkg.Errors {
				fmt.Fprintf(os.Stderr, "WARN: %s: %v\n", pkg.PkgPath, e)
			}
		}
	}

	// ----------------------------------------------------------------- analyze
	store := analyzer.NewStore()

	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil || pkg.Types == nil {
			if *verbose {
				fmt.Fprintf(os.Stderr, "WARN: skipping %s — no type info\n", pkg.PkgPath)
			}
			continue
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "  analyzing %s (%d files)\n", pkg.PkgPath, len(pkg.Syntax))
		}

		insp := inspector.New(pkg.Syntax)
		fset := pkg.Fset
		info := pkg.TypesInfo
		types := pkg.Types

		analyzer.RunNetDial(fset, info, types, insp, store)
		analyzer.RunHTTPClient(fset, info, types, insp, store)
		analyzer.RunHTTPServer(fset, info, types, insp, store)
		analyzer.RunNetListen(fset, info, types, insp, store)
		analyzer.RunGRPC(fset, info, types, insp, store)
		analyzer.RunAmbiguous(fset, info, types, insp, store)
	}

	// ------------------------------------------------------------------ filter
	filtered := make([]analyzer.Candidate, 0, len(store.Candidates))
	for _, c := range store.Candidates {
		level := confOrder[c.Confidence]
		if level < minLevel {
			continue
		}
		if !*inclExternal && c.URLHint == "external" && c.Confidence == "LOW" {
			continue
		}
		if rel, err := filepath.Rel(absRoot, c.File); err == nil {
			c.File = rel
		}
		filtered = append(filtered, c)
	}
	store.Candidates = filtered

	for i := range store.Skipped {
		if rel, err := filepath.Rel(absRoot, store.Skipped[i].File); err == nil {
			store.Skipped[i].File = rel
		}
	}

	// ----------------------------------------------------------------- output
	var out *os.File
	if *outFile != "" {
		out, err = os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: cannot create output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			if err := out.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: closing output file: %v\n", err)
			}
		}()
	} else {
		out = os.Stdout
	}

	// Determine module path from loaded packages.
	modulePath := ""
	for _, pkg := range pkgs {
		if pkg.Module != nil {
			modulePath = pkg.Module.Path
			break
		}
		if modulePath == "" && pkg.PkgPath != "" {
			modulePath = pkg.PkgPath
		}
	}

	if *format == "json" {
		if err := store.WriteJSON(out, modulePath, absRoot, len(fileSet)); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: writing output: %v\n", err)
			os.Exit(1)
		}
	} else {
		writeText(out, store, len(fileSet))
	}
}

func writeText(out *os.File, store *analyzer.Store, filesAnalyzed int) {
	for _, c := range store.Candidates {
		line := fmt.Sprintf("FILE: %s  LINE: %d  TYPE: %s  PATTERN: %s  CONFIDENCE: %s",
			c.File, c.Line, c.Type, c.Pattern, c.Confidence)
		if c.URLHint != "" {
			line += "  URL_HINT: " + c.URLHint
		}
		if c.Notes != "" {
			line += fmt.Sprintf("  NOTES: %q", c.Notes)
		}
		if _, err := fmt.Fprintln(out, line); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: writing output: %v\n", err)
		}
	}
	for _, s := range store.Skipped {
		if _, err := fmt.Fprintf(out, "SKIPPED: %s:%d — %s\n", s.File, s.Line, s.Reason); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: writing output: %v\n", err)
		}
	}

	counts := struct{ total, client, server, ambiguous int }{}
	for _, c := range store.Candidates {
		counts.total++
		switch c.Type {
		case "CLIENT":
			counts.client++
		case "SERVER":
			counts.server++
		case "AMBIGUOUS":
			counts.ambiguous++
		}
	}
	if _, err := fmt.Fprintf(out, "SUMMARY: %d candidates found (%d CLIENT, %d SERVER, %d AMBIGUOUS) in %d files\n",
		counts.total, counts.client, counts.server, counts.ambiguous, filesAnalyzed); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: writing output: %v\n", err)
	}
}
