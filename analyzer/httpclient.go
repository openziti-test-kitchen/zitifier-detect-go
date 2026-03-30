package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/ast/inspector"
)

// RunHTTPClient detects outbound HTTP client calls:
// http.Get, http.Post, http.Head, http.DefaultClient.Do,
// &http.Client{}.Do, http.NewRequest.
func RunHTTPClient(fset *token.FileSet, info *types.Info, pkg *types.Package, insp *inspector.Inspector, store *Store) {
	if IsAlreadyZitified(pkg) {
		return
	}

	// --- package-level functions ---
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
		case pkgPath == "net/http" && (fnName == "Get" || fnName == "Post" || fnName == "Head"):
			urlArg := firstArg(call)
			hint, downgrade := "", false
			if urlArg != nil {
				hint, downgrade = ClassifyURL(urlArg)
			}
			conf := "HIGH"
			notes := ""
			if downgrade {
				conf = "LOW"
			}
			if hint == "external" {
				notes = "URL appears to be an external host — unlikely Ziti candidate"
			}
			store.AddCandidate(fset, call.Pos(), Candidate{
				Type:       "CLIENT",
				Pattern:    "http." + fnName,
				Package:    pkgPath,
				Symbol:     fnName,
				Confidence: conf,
				Context:    FuncName(stack),
				URLHint:    hint,
				Notes:      notes,
			})

		case pkgPath == "net/http" && fnName == "NewRequest":
			// http.NewRequest(method, url, body) — url is args[1]
			urlArg := nthArg(call, 1)
			hint, downgrade := "", false
			if urlArg != nil {
				hint, downgrade = ClassifyURL(urlArg)
			}
			conf := "MEDIUM"
			if downgrade {
				conf = "LOW"
			}
			store.AddCandidate(fset, call.Pos(), Candidate{
				Type:       "CLIENT",
				Pattern:    "http.NewRequest",
				Package:    pkgPath,
				Symbol:     fnName,
				Confidence: conf,
				Context:    FuncName(stack),
				URLHint:    hint,
				Notes:      "manual request construction",
			})

		default:
			// (*http.Client).Do
			checkHTTPClientDo(fset, info, call, stack, store)
		}

		return true
	})

	// --- &http.Client{} composite literals ---
	insp.WithStack([]ast.Node{(*ast.UnaryExpr)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		u := n.(*ast.UnaryExpr)
		comp, ok := u.X.(*ast.CompositeLit)
		if !ok {
			return true
		}
		t := info.TypeOf(comp)
		if t == nil {
			return true
		}
		named, ok := t.(*types.Named)
		if !ok {
			return true
		}
		if named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "net/http" {
			return true
		}
		if named.Obj().Name() != "Client" {
			return true
		}
		pos := fset.Position(u.Pos())
		if IsTestFile(pos.Filename) || IsVendored(pos.Filename) {
			return true
		}
		store.AddCandidate(fset, u.Pos(), Candidate{
			Type:       "CLIENT",
			Pattern:    "&http.Client{}",
			Package:    "net/http",
			Symbol:     "Client",
			Confidence: "HIGH",
			Context:    FuncName(stack),
		})
		return true
	})

	// --- http.DefaultClient selector ---
	insp.WithStack([]ast.Node{(*ast.SelectorExpr)(nil)}, func(n ast.Node, push bool, stack []ast.Node) bool {
		if !push {
			return true
		}
		sel := n.(*ast.SelectorExpr)
		if sel.Sel.Name != "DefaultClient" {
			return true
		}
		obj := info.ObjectOf(sel.Sel)
		if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != "net/http" {
			return true
		}
		pos := fset.Position(sel.Pos())
		if IsTestFile(pos.Filename) || IsVendored(pos.Filename) {
			return true
		}
		store.AddCandidate(fset, sel.Pos(), Candidate{
			Type:       "CLIENT",
			Pattern:    "http.DefaultClient",
			Package:    "net/http",
			Symbol:     "DefaultClient",
			Confidence: "HIGH",
			Context:    FuncName(stack),
		})
		return true
	})
}

func checkHTTPClientDo(fset *token.FileSet, info *types.Info, call *ast.CallExpr, stack []ast.Node, store *Store) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Do" {
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
	if named.Obj().Name() != "Client" {
		return
	}
	pos := fset.Position(call.Pos())
	if IsTestFile(pos.Filename) || IsVendored(pos.Filename) {
		return
	}
	store.AddCandidate(fset, call.Pos(), Candidate{
		Type:       "CLIENT",
		Pattern:    "(*http.Client).Do",
		Package:    "net/http",
		Symbol:     "Do",
		Confidence: "HIGH",
		Context:    FuncName(stack),
		URLHint:    "dynamic",
	})
}

func firstArg(call *ast.CallExpr) ast.Expr {
	if len(call.Args) > 0 {
		return call.Args[0]
	}
	return nil
}

func nthArg(call *ast.CallExpr, n int) ast.Expr {
	if len(call.Args) > n {
		return call.Args[n]
	}
	return nil
}
