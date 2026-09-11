package main

import (
	"fmt"
	"go/ast"
	"strings"
)

func (s *sourceIndex) validateAnchor(anchor sourceAnchor) error {
	for _, file := range s.files {
		if file.path != anchor.Path {
			continue
		}
		for _, decl := range file.ast.Decls {
			shape := s.anchorShape(decl, anchor.Symbol)
			if shape == "" {
				continue
			}
			if shape != anchor.Shape {
				return fmt.Errorf("source anchor changed: %s::%s (%s)", anchor.Path, anchor.Symbol, shape)
			}
			return nil
		}
	}
	return fmt.Errorf("missing source anchor %s::%s", anchor.Path, anchor.Symbol)
}

func (s *sourceIndex) anchorShape(decl ast.Decl, symbol string) string {
	switch decl := decl.(type) {
	case *ast.FuncDecl:
		name := decl.Name.Name
		if decl.Recv != nil {
			name = s.format(decl.Recv.List[0].Type) + "." + name
		}
		if name == symbol {
			return s.format(decl.Type)
		}
	case *ast.GenDecl:
		for _, spec := range decl.Specs {
			switch spec := spec.(type) {
			case *ast.TypeSpec:
				if spec.Name.Name == symbol {
					return s.format(spec.Type)
				}
				if !strings.HasPrefix(symbol, spec.Name.Name+".") {
					continue
				}
				fields, ok := spec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range fields.Fields.List {
					for _, name := range field.Names {
						if spec.Name.Name+"."+name.Name == symbol {
							return s.format(field.Type)
						}
					}
				}
			case *ast.ValueSpec:
				for i, name := range spec.Names {
					if name.Name != symbol {
						continue
					}
					if i < len(spec.Values) {
						return s.format(spec.Values[i])
					}
					if spec.Type != nil {
						return s.format(spec.Type)
					}
				}
			}
		}
	}
	return ""
}
