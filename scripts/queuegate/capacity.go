package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strings"
)

func (s *sourceIndex) capacity(file *sourceFile, expr ast.Expr, seen map[ast.Node]bool) (string, error) {
	if expr == nil {
		return "", nil
	}
	switch expr := expr.(type) {
	case *ast.Ident:
		if expr.Name == "iota" && expr.Obj == nil && len(s.symbols[file.pkg+":iota"]) == 0 {
			return "", fmt.Errorf("unsupported iota capacity constant")
		}
	case *ast.BasicLit:
	case *ast.SelectorExpr:
		base, err := s.capacity(file, expr.X, seen)
		if err != nil {
			return "", err
		}
		if len(s.definitions(file, expr)) == 0 {
			return base + "." + expr.Sel.Name, nil
		}
	case *ast.CallExpr:
		function, err := s.capacity(file, expr.Fun, seen)
		if err != nil {
			return "", err
		}
		args, err := s.capacityList(file, expr.Args, seen)
		if err != nil {
			return "", err
		}
		suffix := ""
		if expr.Ellipsis.IsValid() {
			suffix = "..."
		}
		return function + "(" + args + suffix + ")", nil
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
	case *ast.StarExpr:
		inner, err := s.capacity(file, expr.X, seen)
		return "*" + inner, err
	case *ast.ArrayType:
		length, err := s.capacity(file, expr.Len, seen)
		if err != nil {
			return "", err
		}
		element, err := s.capacity(file, expr.Elt, seen)
		return "[" + length + "]" + element, err
	case *ast.Ellipsis:
		return "...", nil
	case *ast.CompositeLit:
		// A named literal can hide its length in another declaration. Support
		// explicit array/slice types without pretending to resolve type layouts.
		if _, ok := expr.Type.(*ast.ArrayType); !ok {
			return "", fmt.Errorf("unsupported capacity literal type %s", s.format(expr))
		}
		kind, err := s.capacity(file, expr.Type, seen)
		if err != nil {
			return "", err
		}
		elements, err := s.capacityList(file, expr.Elts, seen)
		return kind + "{" + elements + "}", err
	case *ast.KeyValueExpr:
		key, err := s.capacity(file, expr.Key, seen)
		if err != nil {
			return "", err
		}
		value, err := s.capacity(file, expr.Value, seen)
		return key + ": " + value, err
	case *ast.IndexExpr:
		base, err := s.capacity(file, expr.X, seen)
		if err != nil {
			return "", err
		}
		index, err := s.capacity(file, expr.Index, seen)
		return base + "[" + index + "]", err
	case *ast.IndexListExpr:
		base, err := s.capacity(file, expr.X, seen)
		if err != nil {
			return "", err
		}
		indices, err := s.capacityList(file, expr.Indices, seen)
		return base + "[" + indices + "]", err
	case *ast.SliceExpr:
		base, err := s.capacity(file, expr.X, seen)
		if err != nil {
			return "", err
		}
		bounds := []ast.Expr{expr.Low, expr.High}
		if expr.Slice3 {
			bounds = append(bounds, expr.Max)
		}
		var parts []string
		for _, bound := range bounds {
			value, boundErr := s.capacity(file, bound, seen)
			if boundErr != nil {
				return "", boundErr
			}
			parts = append(parts, value)
		}
		return base + "[" + strings.Join(parts, ":") + "]", nil
	default:
		return "", fmt.Errorf("unsupported capacity expression %s", s.format(expr))
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

func (s *sourceIndex) capacityList(file *sourceFile, expressions []ast.Expr, seen map[ast.Node]bool) (string, error) {
	values := make([]string, 0, len(expressions))
	for _, expr := range expressions {
		value, err := s.capacity(file, expr, seen)
		if err != nil {
			return "", err
		}
		values = append(values, value)
	}
	return strings.Join(values, ", "), nil
}

type capacityBinding struct {
	prefix string
	value  ast.Expr
}

func (s *sourceIndex) capacityDefaults(file *sourceFile, decl ast.Decl, capacity ast.Expr) ([]string, error) {
	bindings := make(map[string][]*capacityBinding)
	add := func(name, prefix string, value ast.Expr) {
		bindings[name] = append(bindings[name], &capacityBinding{prefix: prefix, value: value})
	}
	ast.Inspect(decl, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				name := s.format(lhs)
				if i < len(node.Rhs) {
					add(name, name+" "+node.Tok.String()+" ", node.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			for i, id := range node.Names {
				if id.Obj == nil || id.Obj.Kind != ast.Var {
					continue
				}
				if i < len(node.Values) {
					add(id.Name, "var "+id.Name+" = ", node.Values[i])
				} else {
					add(id.Name, "var "+s.format(node), nil)
				}
			}
		}
		return true
	})
	var values []string
	var resolveErr error
	seen := make(map[*capacityBinding]bool)
	var visit func(ast.Expr)
	visit = func(expression ast.Expr) {
		if expression == nil {
			return
		}
		ast.Inspect(expression, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok && (s.builtinCapacityCall(file, call, "len") || s.builtinCapacityCall(file, call, "cap")) {
				for _, arg := range call.Args {
					s.collectionCapacityInputs(file, arg, visit)
				}
				return false
			}
			expr, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			for _, binding := range bindings[s.format(expr)] {
				if seen[binding] {
					continue
				}
				seen[binding] = true
				expanded, err := s.capacity(file, binding.value, make(map[ast.Node]bool))
				if err != nil {
					resolveErr = err
					continue
				}
				values = append(values, binding.prefix+expanded)
				visit(binding.value)
			}
			return true
		})
	}
	visit(capacity)
	slices.Sort(values)
	return slices.Compact(values), resolveErr
}

func (s *sourceIndex) builtinCapacityCall(file *sourceFile, call *ast.CallExpr, name string) bool {
	id, ok := callBase(call.Fun).(*ast.Ident)
	return ok && id.Name == name && id.Obj == nil && len(s.symbols[file.pkg+":"+name]) == 0
}

// Runtime collections keep symbolic lengths. Only explicit scalar bounds in
// their construction or slicing belong to the local capacity-input graph.
func (s *sourceIndex) collectionCapacityInputs(file *sourceFile, expr ast.Expr, visit func(ast.Expr)) {
	switch expr := expr.(type) {
	case *ast.ParenExpr:
		s.collectionCapacityInputs(file, expr.X, visit)
	case *ast.StarExpr:
		s.collectionCapacityInputs(file, expr.X, visit)
	case *ast.UnaryExpr:
		s.collectionCapacityInputs(file, expr.X, visit)
	case *ast.SliceExpr:
		visit(expr.Low)
		visit(expr.High)
		visit(expr.Max)
		s.collectionCapacityInputs(file, expr.X, visit)
	case *ast.CallExpr:
		if s.builtinCapacityCall(file, expr, "make") && len(expr.Args) > 0 {
			for _, size := range expr.Args[1:] {
				visit(size)
			}
		}
	}
}
