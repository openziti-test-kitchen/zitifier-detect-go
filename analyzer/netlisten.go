package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ast/inspector"
)

// RunNetListen detects net.Listen and net.ListenTCP SERVER calls.
func RunNetListen(fset *token.FileSet, info *types.Info, pkg *types.Package, insp *inspector.Inspector, store *Store) {
	if IsAlreadyZitified(pkg) {
		return
	}

	insp.WithStack([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
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
		case "Listen":
			pattern = "net.Listen"
		case "ListenTCP":
			pattern = "net.ListenTCP"
		default:
			return true
		}

		confidence, skip, skipReason := networkArgConfidence(call, pattern, 0)
		if skip {
			store.AddSkipped(fset, call.Pos(), Skipped{
				Pattern: pattern,
				Reason:  skipReason,
			})
			return true
		}

		store.AddCandidate(fset, call.Pos(), Candidate{
			Type:       "SERVER",
			Pattern:    pattern,
			Package:    pkgPath,
			Symbol:     fnName,
			Confidence: confidence,
			Context:    FuncName(stack),
		})
		return true
	})
}
