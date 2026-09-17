package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
)

const modulePath = "github.com/pidginhost/csm"

type allocation struct {
	ID       string   `json:"id"`
	Path     string   `json:"path"`
	Owner    string   `json:"owner"`
	Target   string   `json:"target"`
	Kind     string   `json:"kind"`
	Source   string   `json:"source"`
	Capacity string   `json:"capacity"`
	Defaults []string `json:"defaults,omitempty"`
}

type sourceFile struct {
	path, pkg  string
	ast        *ast.File
	imports    map[string]string
	dotImports map[string]bool
}

type sourceSymbol struct {
	file  *sourceFile
	node  ast.Node
	value ast.Expr
	kind  token.Token
}

type sourceIndex struct {
	fset     *token.FileSet
	files    []*sourceFile
	symbols  map[string][]sourceSymbol
	external types.Importer
}

func readSources(root fs.FS) (*sourceIndex, error) {
	index := &sourceIndex{fset: token.NewFileSet(), symbols: make(map[string][]sourceSymbol)}
	err := fs.WalkDir(root, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if name != "." && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor" || entry.Name() == "testdata") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(root, name)
		if err != nil {
			return err
		}
		parsed, err := parser.ParseFile(index.fset, name, data, 0)
		if err != nil {
			return err
		}
		file := &sourceFile{path: name, pkg: path.Dir(name) + ":" + parsed.Name.Name, ast: parsed, imports: make(map[string]string), dotImports: make(map[string]bool)}
		index.files = append(index.files, file)
		index.collectSymbols(file)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return index, index.resolveImports()
}

func (s *sourceIndex) resolveImports() error {
	names := make(map[string][]string)
	for _, file := range s.files {
		names[path.Dir(file.path)] = append(names[path.Dir(file.path)], file.ast.Name.Name)
	}
	for _, file := range s.files {
		for _, spec := range file.ast.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			aliases := []string{path.Base(importPath)}
			if spec.Name != nil {
				aliases = []string{spec.Name.Name}
			} else if strings.HasPrefix(importPath, modulePath+"/") {
				if declared := names[strings.TrimPrefix(importPath, modulePath+"/")]; len(declared) != 0 {
					aliases = declared
				}
			}
			for _, alias := range aliases {
				if alias == "." {
					file.dotImports[importPath] = true
				}
				file.imports[alias] = importPath
			}
		}
	}
	return nil
}

func (s *sourceIndex) collectSymbols(file *sourceFile) {
	for _, decl := range file.ast.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			if decl.Recv == nil {
				s.addSymbol(file, decl.Name.Name, sourceSymbol{file: file, node: decl, kind: token.FUNC})
			}
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					s.addSymbol(file, spec.Name.Name, sourceSymbol{file: file, node: spec, value: spec.Type, kind: token.TYPE})
				case *ast.ValueSpec:
					for i, name := range spec.Names {
						var value ast.Expr
						if i < len(spec.Values) {
							value = spec.Values[i]
						}
						s.addSymbol(file, name.Name, sourceSymbol{file: file, node: spec, value: value, kind: decl.Tok})
					}
				}
			}
		}
	}
}

func (s *sourceIndex) addSymbol(file *sourceFile, name string, symbol sourceSymbol) {
	key := file.pkg + ":" + name
	s.symbols[key] = append(s.symbols[key], symbol)
}

func (s *sourceIndex) format(node ast.Node) string {
	var out bytes.Buffer
	if err := printer.Fprint(&out, s.fset, node); err != nil {
		panic(err)
	}
	return out.String()
}

func scanSources(root fs.FS) ([]allocation, error) {
	index, err := readSources(root)
	if err != nil {
		return nil, err
	}
	return index.allocations()
}

func (s *sourceIndex) allocations() ([]allocation, error) {
	var result []allocation
	for _, file := range s.files {
		counts := make(map[string]int)
		for _, decl := range file.ast.Decls {
			found, err := s.scanDeclaration(file, decl, counts)
			if err != nil {
				return nil, err
			}
			result = append(result, found...)
		}
	}
	slices.SortFunc(result, func(a, b allocation) int { return strings.Compare(a.ID, b.ID) })
	return result, nil
}

func (s *sourceIndex) scanDeclaration(file *sourceFile, decl ast.Decl, counts map[string]int) ([]allocation, error) {
	owner := "package"
	if fn, ok := decl.(*ast.FuncDecl); ok {
		owner = fn.Name.Name
		if fn.Recv != nil {
			owner = s.format(fn.Recv.List[0].Type) + "." + owner
		}
	}
	var stack []ast.Node
	var found []allocation
	var scanErr error
	ast.Inspect(decl, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, node)
		if scanErr != nil {
			return true
		}
		if constructor := s.constructor(file, node); constructor != "" && !constructorCalled(stack) {
			scanErr = fmt.Errorf("%s: indirect channel constructor requires an ownership decision", s.fset.Position(node.Pos()))
			return true
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		kind, capacity, err := s.allocationCall(file, call)
		if err != nil {
			scanErr = fmt.Errorf("%s: %w", s.fset.Position(call.Pos()), err)
			return true
		}
		if kind == "" {
			return true
		}
		target := "expression"
		for i := len(stack) - 2; i >= 0; i-- {
			switch parent := stack[i].(type) {
			case *ast.KeyValueExpr:
				target = s.format(parent.Key)
			case *ast.AssignStmt:
				var names []string
				for _, lhs := range parent.Lhs {
					names = append(names, s.format(lhs))
				}
				target = strings.Join(names, ",")
			case *ast.ValueSpec:
				var names []string
				for _, name := range parent.Names {
					names = append(names, name.Name)
				}
				target = strings.Join(names, ",")
			default:
				continue
			}
			break
		}
		capacityText := "0"
		var defaults []string
		if capacity != nil {
			capacityText, scanErr = s.capacity(file, capacity, make(map[ast.Node]bool))
			if scanErr != nil {
				return true
			}
			defaults, scanErr = s.capacityDefaults(file, decl, capacity)
			if scanErr != nil {
				return true
			}
		}
		base := file.path + "::" + owner + "::" + target + "::" + kind
		counts[base]++
		found = append(found, allocation{ID: fmt.Sprintf("%s::%d", base, counts[base]), Path: file.path, Owner: owner, Target: target, Kind: kind, Source: s.format(call), Capacity: capacityText, Defaults: defaults})
		return true
	})
	return found, scanErr
}

func callBase(expr ast.Expr) ast.Expr {
	for {
		switch node := expr.(type) {
		case *ast.ParenExpr:
			expr = node.X
		case *ast.IndexExpr:
			expr = node.X
		case *ast.IndexListExpr:
			expr = node.X
		default:
			return expr
		}
	}
}

func (s *sourceIndex) constructor(file *sourceFile, node ast.Node) string {
	name, importPath := "", ""
	switch node := node.(type) {
	case *ast.SelectorExpr:
		base, ok := node.X.(*ast.Ident)
		if !ok || base.Obj != nil {
			return ""
		}
		name, importPath = node.Sel.Name, file.imports[base.Name]
	case *ast.Ident:
		if node.Obj != nil {
			return ""
		}
		name = node.Name
		switch {
		case name == "NewChannel" && file.dotImports[modulePath+"/internal/queuehealth"]:
			importPath = modulePath + "/internal/queuehealth"
		case name == "MakeChan" && file.dotImports["reflect"]:
			importPath = "reflect"
		}
	}
	if name == "NewChannel" && importPath == modulePath+"/internal/queuehealth" {
		return "accounted_channel"
	}
	if name == "MakeChan" && importPath == "reflect" {
		return "reflect"
	}
	return ""
}

func constructorCalled(stack []ast.Node) bool {
	child := stack[len(stack)-1]
	for i := len(stack) - 2; i >= 0; i-- {
		switch parent := stack[i].(type) {
		case *ast.ParenExpr:
			if parent.X != child {
				return false
			}
		case *ast.IndexExpr:
			if parent.X != child {
				return false
			}
		case *ast.IndexListExpr:
			if parent.X != child {
				return false
			}
		case *ast.CallExpr:
			return parent.Fun == child
		case *ast.SelectorExpr:
			// A selector's field identifier is not a dot-import reference.
			return parent.Sel == child
		default:
			return false
		}
		child = stack[i]
	}
	return false
}

func (s *sourceIndex) allocationCall(file *sourceFile, call *ast.CallExpr) (string, ast.Expr, error) {
	base := callBase(call.Fun)
	if kind := s.constructor(file, base); kind != "" {
		if kind == "reflect" {
			return "", nil, fmt.Errorf("reflective channel allocation requires explicit support")
		}
		if len(call.Args) == 0 {
			return "", nil, fmt.Errorf("channel constructor has no capacity")
		}
		return kind, call.Args[0], nil
	}
	id, ok := base.(*ast.Ident)
	if !ok || id.Name != "make" || id.Obj != nil {
		return "", nil, nil
	}
	if len(s.symbols[file.pkg+":make"]) != 0 {
		return "", nil, fmt.Errorf("ambiguous make shadowing across source files")
	}
	if len(call.Args) == 0 {
		return "", nil, fmt.Errorf("make has no type")
	}
	channel, err := s.channelType(file, call.Args[0], make(map[ast.Node]bool))
	if err != nil || !channel {
		return "", nil, err
	}
	var capacity ast.Expr
	if len(call.Args) > 1 {
		capacity = call.Args[1]
	}
	return "channel", capacity, nil
}
