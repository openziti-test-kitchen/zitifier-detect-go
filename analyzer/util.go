package analyzer

import (
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"
)

// IsTestFile returns true if the filename ends in _test.go.
func IsTestFile(filename string) bool {
	return strings.HasSuffix(filename, "_test.go")
}

// IsVendored returns true if the file path contains a vendor/ segment.
func IsVendored(filename string) bool {
	cleaned := filepath.ToSlash(filename)
	return strings.Contains(cleaned, "/vendor/") ||
		strings.HasPrefix(cleaned, "vendor/")
}

// IsAlreadyZitified returns true if the package imports the OpenZiti Go SDK.
func IsAlreadyZitified(pkg *types.Package) bool {
	if pkg == nil {
		return false
	}
	for _, imp := range pkg.Imports() {
		if strings.HasPrefix(imp.Path(), "github.com/openziti/sdk-golang") {
			return true
		}
	}
	return false
}

// FuncName returns the name of the enclosing function or method by walking
// up the AST stack.
func FuncName(stack []ast.Node) string {
	for i := len(stack) - 1; i >= 0; i-- {
		switch n := stack[i].(type) {
		case *ast.FuncDecl:
			if n.Recv != nil && len(n.Recv.List) > 0 {
				recv := ""
				if t, ok := n.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := t.X.(*ast.Ident); ok {
						recv = "*" + id.Name
					}
				} else if id, ok := n.Recv.List[0].Type.(*ast.Ident); ok {
					recv = id.Name
				}
				if recv != "" {
					return "func (" + recv + ") " + n.Name.Name
				}
			}
			return "func " + n.Name.Name
		case *ast.FuncLit:
			return "func literal"
		}
	}
	return ""
}

// StringLiteralValue returns the unquoted value of a string basic literal,
// or ("", false) if the expression is not a string literal.
func StringLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return "", false
	}
	v := lit.Value
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1], true
	}
	return "", false
}

// IsTCPNetwork returns true for network strings Ziti can replace.
func IsTCPNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return true
	}
	return false
}

// IsSkippableNetwork returns true for network types Ziti cannot replace.
func IsSkippableNetwork(network string) bool {
	switch network {
	case "unix", "unixgram", "unixpacket", "udp", "udp4", "udp6", "ip", "ip4", "ip6":
		return true
	}
	return false
}

// ClassifyURL returns a url_hint string and whether confidence should be
// lowered to LOW based on inspection of the URL argument expression.
func ClassifyURL(expr ast.Expr) (hint string, downgrade bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		val, ok := StringLiteralValue(e)
		if !ok {
			return "dynamic", false
		}
		lower := strings.ToLower(val)
		if strings.HasPrefix(lower, "http://localhost") ||
			strings.HasPrefix(lower, "https://localhost") ||
			strings.HasPrefix(lower, "http://127.0.0.1") ||
			strings.HasPrefix(lower, "https://127.0.0.1") {
			return "localhost", true
		}
		externalDomains := []string{
			"github.com", "googleapis.com", "amazonaws.com",
			"api.stripe.com", "api.sendgrid.com", "slack.com",
			"twilio.com", "pagerduty.com", "cloudflare.com",
		}
		for _, d := range externalDomains {
			if strings.Contains(lower, d) {
				return "external", true
			}
		}
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			return "internal", false
		}
		return "dynamic", false

	case *ast.CallExpr, *ast.BinaryExpr:
		return "dynamic", false

	case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr:
		return "dynamic", false
	}
	return "", false
}
