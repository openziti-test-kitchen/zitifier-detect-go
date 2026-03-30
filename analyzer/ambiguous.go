package analyzer

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ast/inspector"
)

// RunAmbiguous detects WebSocket and raw TLS patterns that have no Ziti SDK
// drop-in. All results go to the skipped list, not candidates.
func RunAmbiguous(fset *token.FileSet, info *types.Info, pkg *types.Package, insp *inspector.Inspector, store *Store) {
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
		if pkgPath == "" {
			return true
		}

		var pattern, reason string

		switch {
		case strings.HasPrefix(pkgPath, "github.com/gorilla/websocket"):
			switch fnName {
			case "Dial", "DialContext":
				pattern = "gorilla/websocket.Dialer." + fnName
				reason = "gorilla/websocket — no Ziti SDK drop-in; requires custom net.Conn shim"
			case "Upgrade":
				pattern = "gorilla/websocket.Upgrader.Upgrade"
				reason = "gorilla/websocket — no Ziti SDK drop-in for server-side upgrade"
			default:
				return true
			}

		case strings.HasPrefix(pkgPath, "nhooyr.io/websocket"):
			switch fnName {
			case "Dial":
				pattern = "nhooyr.io/websocket.Dial"
				reason = "nhooyr.io/websocket — no Ziti SDK drop-in"
			case "Accept":
				pattern = "nhooyr.io/websocket.Accept"
				reason = "nhooyr.io/websocket — no Ziti SDK drop-in for server-side accept"
			default:
				return true
			}

		case pkgPath == "crypto/tls" && fnName == "Dial":
			pattern = "tls.Dial"
			reason = "crypto/tls.Dial — Ziti provides E2E encryption; TLS on top may be redundant; manual review required"

		default:
			return true
		}

		store.AddSkipped(fset, call.Pos(), Skipped{
			Pattern: pattern,
			Reason:  reason,
		})
		return true
	})
}

