package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ast/inspector"
)

// RunGRPC detects grpc.Dial, grpc.DialContext, and grpc.NewClient calls.
func RunGRPC(fset *token.FileSet, info *types.Info, pkg *types.Package, insp *inspector.Inspector, store *Store) {
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
		if pkgPath != "google.golang.org/grpc" {
			return true
		}
		switch fnName {
		case "Dial", "DialContext", "NewClient":
		default:
			return true
		}

		store.AddCandidate(fset, call.Pos(), Candidate{
			Type:       "CLIENT",
			Pattern:    "grpc." + fnName,
			Package:    pkgPath,
			Symbol:     fnName,
			Confidence: "HIGH",
			Context:    FuncName(stack),
			Notes:      "gRPC — requires custom WithContextDialer shim",
		})
		return true
	})
}
