package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ast/inspector"
)

// RunNetDial detects net.Dial / net.DialContext / net.DialTCP CLIENT calls.
func RunNetDial(fset *token.FileSet, info *types.Info, pkg *types.Package, insp *inspector.Inspector, store *Store) {
	if IsAlreadyZitified(pkg) {
		return
	}

	nodeFilter := []ast.Node{(*ast.CallExpr)(nil)}

	insp.WithStack(nodeFilter, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		call := n.(*ast.CallExpr)

		pos := fset.Position(call.Pos())
		if IsTestFile(pos.Filename) || IsVendored(pos.Filename) {
			return true
		}

		pkgPath, fnName := resolveCallee(info, call)
		if pkgPath != "net" {
			return true
		}

		var pattern string
		switch fnName {
		case "Dial":
			pattern = "net.Dial"
		case "DialContext":
			pattern = "net.DialContext"
		case "DialTCP":
			pattern = "net.DialTCP"
		default:
			return true
		}

		// For DialContext the network arg is at index 1 (ctx is 0).
		networkArgIdx := 0
		if fnName == "DialContext" {
			networkArgIdx = 1
		}

		confidence, skip, skipReason := networkArgConfidence(call, pattern, networkArgIdx)
		if skip {
			store.AddSkipped(fset, call.Pos(), Skipped{
				Pattern: pattern,
				Reason:  skipReason,
			})
			return true
		}

		store.AddCandidate(fset, call.Pos(), Candidate{
			Type:       "CLIENT",
			Pattern:    pattern,
			Package:    pkgPath,
			Symbol:     fnName,
			Confidence: confidence,
			Context:    FuncName(stack),
		})
		return true
	})
}

// networkArgConfidence inspects the network argument at argIndex.
// Returns skip=true for non-Ziti network types (unix, udp, …).
func networkArgConfidence(call *ast.CallExpr, pattern string, argIndex int) (confidence string, skip bool, reason string) {
	if len(call.Args) <= argIndex {
		return "MEDIUM", false, ""
	}
	netVal, isLit := StringLiteralValue(call.Args[argIndex])
	if !isLit {
		return "MEDIUM", false, ""
	}
	if IsSkippableNetwork(netVal) {
		return "", true, pattern + ": network=" + netVal + " — not Ziti-compatible"
	}
	if IsTCPNetwork(netVal) {
		return "HIGH", false, ""
	}
	return "MEDIUM", false, ""
}

// resolveCallee is a package-private helper used by multiple analyzers.
func resolveCallee(info *types.Info, call *ast.CallExpr) (pkgPath, name string) {
	var ident *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.Ident:
		ident = f
	case *ast.SelectorExpr:
		ident = f.Sel
	default:
		return "", ""
	}
	obj := info.ObjectOf(ident)
	if obj == nil {
		return "", ""
	}
	p := obj.Pkg()
	if p == nil {
		return "", ""
	}
	return p.Path(), obj.Name()
}
