package main

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/token"
	"go/types"
	"path"
	"slices"
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
		for _, imported := range s.files {
			if path.Dir(imported.path) == dir {
				definitions = s.symbols[imported.pkg+":"+expr.Sel.Name]
				break
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

func (s *sourceIndex) capacity(file *sourceFile, expr ast.Expr, seen map[ast.Node]bool) (string, error) {
	switch expr := expr.(type) {
	case *ast.Ident:
		if expr.Name == "iota" && expr.Obj == nil && len(s.symbols[file.pkg+":iota"]) == 0 {
			return "", fmt.Errorf("unsupported iota capacity constant")
		}
	case *ast.CallExpr:
		args := make([]string, 0, len(expr.Args))
		for _, arg := range expr.Args {
			value, err := s.capacity(file, arg, seen)
			if err != nil {
				return "", err
			}
			args = append(args, value)
		}
		suffix := ""
		if expr.Ellipsis.IsValid() {
			suffix = "..."
		}
		return s.format(expr.Fun) + "(" + strings.Join(args, ", ") + suffix + ")", nil
	case *ast.ParenExpr:
		inner, err := s.capacity(file, expr.X, seen)
		return "(" + inner + ")", err
	case *ast.BinaryExpr:
		left, err := s.capacity(file, expr.X, seen)
		if err != nil {
			return "", err
		}
		right, err := s.capacity(file, expr.Y, seen)
		return "(" + left + " " + expr.Op.String() + " " + right + ")", err
	case *ast.UnaryExpr:
		inner, err := s.capacity(file, expr.X, seen)
		return expr.Op.String() + inner, err
	}
	definitions := s.definitions(file, expr)
	var values []string
	for _, definition := range definitions {
		if definition.kind != token.CONST {
			continue
		}
		if definition.value == nil || seen[definition.value] {
			return "", fmt.Errorf("unresolved capacity constant %s", s.format(expr))
		}
		seen[definition.value] = true
		value, err := s.capacity(definition.file, definition.value, seen)
		delete(seen, definition.value)
		if err != nil {
			return "", err
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return s.format(expr), nil
	}
	slices.Sort(values)
	return strings.Join(slices.Compact(values), " | "), nil
}

func (s *sourceIndex) capacityDefaults(file *sourceFile, decl ast.Decl, capacity ast.Expr) ([]string, error) {
	name := s.format(capacity)
	var values []string
	var resolveErr error
	ast.Inspect(decl, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assignment.Lhs {
			if s.format(lhs) != name || i >= len(assignment.Rhs) {
				continue
			}
			value, err := s.capacity(file, assignment.Rhs[i], make(map[ast.Node]bool))
			if err != nil {
				resolveErr = err
				continue
			}
			values = append(values, name+" "+assignment.Tok.String()+" "+value)
		}
		return true
	})
	slices.Sort(values)
	return slices.Compact(values), resolveErr
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
