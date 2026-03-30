package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ast/inspector"
)

// RunHTTPServer detects http.ListenAndServe, http.ListenAndServeTLS,
// (*http.Server).ListenAndServe, and (*http.Server).Serve calls.
func RunHTTPServer(fset *token.FileSet, info *types.Info, pkg *types.Package, insp *inspector.Inspector, store *Store) {
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

		switch {
		case pkgPath == "net/http" && (fnName == "ListenAndServe" || fnName == "ListenAndServeTLS"):
			store.AddCandidate(fset, call.Pos(), Candidate{
				Type:       "SERVER",
				Pattern:    "http." + fnName,
				Package:    pkgPath,
				Symbol:     fnName,
				Confidence: "HIGH",
				Context:    FuncName(stack),
			})

		default:
			checkHTTPServerMethod(fset, info, call, stack, store)
		}

		return true
	})
}

// checkHTTPServerMethod detects method calls on *http.Server.
func checkHTTPServerMethod(fset *token.FileSet, info *types.Info, call *ast.CallExpr, stack []ast.Node, store *Store) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	switch sel.Sel.Name {
	case "ListenAndServe", "ListenAndServeTLS", "Serve":
	default:
		return
	}

	t := info.TypeOf(sel.X)
	if t == nil {
		return
	}
	if pt, ok := t.(*types.Pointer); ok {
		t = pt.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return
	}
	if named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "net/http" {
		return
	}
	if named.Obj().Name() != "Server" {
		return
	}

	pos := fset.Position(call.Pos())
	if IsTestFile(pos.Filename) || IsVendored(pos.Filename) {
		return
	}

	store.AddCandidate(fset, call.Pos(), Candidate{
		Type:       "SERVER",
		Pattern:    "(*http.Server)." + sel.Sel.Name,
		Package:    "net/http",
		Symbol:     sel.Sel.Name,
		Confidence: "HIGH",
		Context:    FuncName(stack),
	})
}
