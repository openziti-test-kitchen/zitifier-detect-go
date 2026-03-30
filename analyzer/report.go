package analyzer

import (
	"encoding/json"
	"go/token"
	"io"
	"os"
)

// Candidate represents a single Zitification candidate found by analysis.
type Candidate struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Col        int    `json:"col"`
	Type       string `json:"type"`       // CLIENT, SERVER, AMBIGUOUS
	Pattern    string `json:"pattern"`
	Package    string `json:"package"`
	Symbol     string `json:"symbol"`
	Confidence string `json:"confidence"` // HIGH, MEDIUM, LOW
	Context    string `json:"context"`    // enclosing function/method name
	URLHint    string `json:"url_hint"`   // dynamic, external, internal, localhost, ""
	Notes      string `json:"notes"`
}

// Skipped represents a pattern that was found but excluded from candidates.
type Skipped struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Reason  string `json:"reason"`
	Pattern string `json:"pattern"`
}

// Summary holds aggregate counts.
type Summary struct {
	TotalCandidates int `json:"total_candidates"`
	Client          int `json:"client"`
	Server          int `json:"server"`
	Ambiguous       int `json:"ambiguous"`
	Skipped         int `json:"skipped"`
	FilesAnalyzed   int `json:"files_analyzed"`
}

// Report is the top-level JSON output structure.
type Report struct {
	SchemaVersion string      `json:"schema_version"`
	Tool          string      `json:"tool"`
	Module        string      `json:"module"`
	Root          string      `json:"root"`
	Candidates    []Candidate `json:"candidates"`
	Skipped       []Skipped   `json:"skipped"`
	Summary       Summary     `json:"summary"`
}

// Store accumulates results across all analyzer passes.
// It is safe to use from a single goroutine (analysis passes run sequentially
// per package within go/analysis).
type Store struct {
	Candidates []Candidate
	Skipped    []Skipped
}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) AddCandidate(fset *token.FileSet, pos token.Pos, c Candidate) {
	if fset != nil {
		p := fset.Position(pos)
		c.File = p.Filename
		c.Line = p.Line
		c.Col = p.Column
	}
	s.Candidates = append(s.Candidates, c)
}

func (s *Store) AddSkipped(fset *token.FileSet, pos token.Pos, sk Skipped) {
	if fset != nil {
		p := fset.Position(pos)
		sk.File = p.Filename
		sk.Line = p.Line
	}
	s.Skipped = append(s.Skipped, sk)
}

// WriteJSON emits the final report. Pass out=nil to write to stdout.
func (s *Store) WriteJSON(out io.Writer, module, root string, filesAnalyzed int) error {
	if out == nil {
		out = os.Stdout
	}

	counts := Summary{FilesAnalyzed: filesAnalyzed}
	for _, c := range s.Candidates {
		counts.TotalCandidates++
		switch c.Type {
		case "CLIENT":
			counts.Client++
		case "SERVER":
			counts.Server++
		case "AMBIGUOUS":
			counts.Ambiguous++
		}
	}
	counts.Skipped = len(s.Skipped)

	report := Report{
		SchemaVersion: "1",
		Tool:          "zitifier-detect-go",
		Module:        module,
		Root:          root,
		Candidates:    s.Candidates,
		Skipped:       s.Skipped,
		Summary:       counts,
	}

	if report.Candidates == nil {
		report.Candidates = []Candidate{}
	}
	if report.Skipped == nil {
		report.Skipped = []Skipped{}
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
