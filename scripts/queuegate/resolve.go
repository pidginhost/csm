package main

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/token"
	"go/types"
	"path"
	"strings"
)

func (s *sourceIndex) definitions(file *sourceFile, expr ast.Expr) []sourceSymbol {
	switch expr := expr.(type) {
	case *ast.Ident:
		if expr.Obj != nil {
			switch decl := expr.Obj.Decl.(type) {
			case *ast.TypeSpec:
				return []sourceSymbol{{file: file, node: decl, value: decl.Type, kind: token.TYPE}}
			case *ast.ValueSpec:
				if expr.Obj.Kind == ast.Con {
					for i, name := range decl.Names {
						if name.Name == expr.Name {
							var value ast.Expr
							if i < len(decl.Values) {
								value = decl.Values[i]
							}
							return []sourceSymbol{{file: file, node: decl, value: value, kind: token.CONST}}
						}
					}
				}
			}
			return nil
		}
		return s.symbols[file.pkg+":"+expr.Name]
	case *ast.SelectorExpr:
		alias, ok := expr.X.(*ast.Ident)
		if !ok || alias.Obj != nil {
			return nil
		}
		importPath := file.imports[alias.Name]
		if !strings.HasPrefix(importPath, modulePath+"/") {
			return nil
		}
		dir := strings.TrimPrefix(importPath, modulePath+"/")
		var definitions []sourceSymbol
		seen := make(map[string]bool)
		for _, imported := range s.files {
			if path.Dir(imported.path) == dir && !seen[imported.pkg] {
				seen[imported.pkg] = true
				definitions = append(definitions, s.symbols[imported.pkg+":"+expr.Sel.Name]...)
			}
		}
		return definitions
	}
	return nil
}

func (s *sourceIndex) channelType(file *sourceFile, expr ast.Expr, seen map[ast.Node]bool) (bool, error) {
	expr = callBase(expr)
	switch expr.(type) {
	case *ast.ChanType:
		return true, nil
	case *ast.ArrayType, *ast.MapType:
		return false, nil
	}
	definitions := s.definitions(file, expr)
	if len(definitions) == 0 {
		resolved, err := s.externalType(file, expr)
		if err != nil {
			return false, err
		}
		if resolved != nil {
			switch resolved.Underlying().(type) {
			case *types.Chan:
				return true, nil
			case *types.Slice, *types.Map:
				return false, nil
			}
		}
		return false, fmt.Errorf("unresolved make type %s", s.format(expr))
	}
	var channel bool
	for i, definition := range definitions {
		if definition.kind != token.TYPE {
			return false, fmt.Errorf("unresolved make type %s", s.format(expr))
		}
		if seen[definition.node] {
			return false, fmt.Errorf("cyclic make type %s", s.format(expr))
		}
		seen[definition.node] = true
		kind, err := s.channelType(definition.file, definition.value, seen)
		delete(seen, definition.node)
		if err != nil {
			return false, err
		}
		if i != 0 && channel != kind {
			return false, fmt.Errorf("ambiguous make type across build variants: %s", s.format(expr))
		}
		channel = kind
	}
	return channel, nil
}

func (s *sourceIndex) externalType(file *sourceFile, expr ast.Expr) (types.Type, error) {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return nil, nil
	}
	alias, ok := selector.X.(*ast.Ident)
	if !ok || alias.Obj != nil {
		return nil, nil
	}
	importPath := file.imports[alias.Name]
	if importPath == "" || strings.HasPrefix(importPath, modulePath+"/") {
		return nil, nil
	}
	if s.external == nil {
		s.external = importer.ForCompiler(s.fset, "source", nil)
	}
	pkg, err := s.external.Import(importPath)
	if err != nil {
		return nil, fmt.Errorf("resolve imported make type %s: %w", s.format(expr), err)
	}
	object, ok := pkg.Scope().Lookup(selector.Sel.Name).(*types.TypeName)
	if !ok {
		return nil, fmt.Errorf("unresolved make type %s", s.format(expr))
	}
	return object.Type(), nil
}
