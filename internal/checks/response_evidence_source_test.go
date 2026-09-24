package checks

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
)

const producerModule = "github.com/pidginhost/csm/"

// The inventory reads every build variant without compiling it. Resolve only
// source-declared types; an unsupported expression stays unknown, never proof
// that a write or literal is unrelated to a Finding.
type producerType struct {
	file *ast.File
	expr ast.Expr
}

type producerDecl struct {
	file *ast.File
	node ast.Node
}

type producerPackage struct {
	names   map[string][]producerDecl
	methods map[string][]producerDecl
}

type producerSources struct {
	packages map[string]*producerPackage
	files    map[*ast.File]*producerPackage
	owners   map[ast.Node]*ast.File
	parents  map[ast.Node]ast.Node
}

func newProducerSources(root string, dirs map[string][]*ast.File) *producerSources {
	s := &producerSources{
		packages: map[string]*producerPackage{}, files: map[*ast.File]*producerPackage{},
		owners: map[ast.Node]*ast.File{}, parents: map[ast.Node]ast.Node{},
	}
	for dir, files := range dirs {
		pkg := &producerPackage{names: map[string][]producerDecl{}, methods: map[string][]producerDecl{}}
		rel, _ := filepath.Rel(root, dir)
		s.packages[producerModule+filepath.ToSlash(rel)] = pkg
		for _, f := range files {
			s.files[f] = pkg
			var stack []ast.Node
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return false
				}
				s.owners[n] = f
				if len(stack) > 0 {
					s.parents[n] = stack[len(stack)-1]
				}
				stack = append(stack, n)
				return true
			})
			for _, decl := range f.Decls {
				add := func(name string, node ast.Node) { pkg.names[name] = append(pkg.names[name], producerDecl{f, node}) }
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						switch v := spec.(type) {
						case *ast.TypeSpec:
							add(v.Name.Name, v)
						case *ast.ValueSpec:
							for _, name := range v.Names {
								add(name.Name, v)
							}
						}
					}
				case *ast.FuncDecl:
					if d.Recv == nil {
						add(d.Name.Name, d)
					} else if len(d.Recv.List) == 1 {
						recv := d.Recv.List[0].Type
						if p, ok := recv.(*ast.StarExpr); ok {
							recv = p.X
						}
						if id, ok := recv.(*ast.Ident); ok {
							key := id.Name + "." + d.Name.Name
							pkg.methods[key] = append(pkg.methods[key], producerDecl{f, d})
						}
					}
				}
			}
		}
	}
	return s
}

func producerImport(f *ast.File, name string) string {
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		alias := filepath.Base(path)
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		if alias == name {
			return path
		}
	}
	return ""
}

func (s *producerSources) declaration(f *ast.File, e ast.Expr) producerDecl {
	var candidates []producerDecl
	switch v := ast.Unparen(e).(type) {
	case *ast.Ident:
		if v.Obj != nil {
			n, ok := v.Obj.Decl.(ast.Node)
			if ok {
				return producerDecl{s.owners[n], n}
			}
		}
		candidates = s.files[f].names[v.Name]
	case *ast.SelectorExpr:
		if id, ok := v.X.(*ast.Ident); ok && id.Obj == nil {
			if pkg := s.packages[producerImport(f, id.Name)]; pkg != nil {
				candidates = pkg.names[v.Sel.Name]
			}
		}
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return producerDecl{}
}

func (s *producerSources) finding(t producerType) bool {
	switch v := ast.Unparen(t.expr).(type) {
	case *ast.SelectorExpr:
		id, ok := v.X.(*ast.Ident)
		return ok && id.Obj == nil && v.Sel.Name == "Finding" && producerImport(t.file, id.Name) == producerModule+"internal/alert"
	case *ast.Ident:
		return v.Name == "Finding" && (t.file.Name.Name == "alert" || (v.Obj == nil && producerImport(t.file, ".") == producerModule+"internal/alert"))
	}
	return false
}

// shape follows aliases, defined types and pointers. Cycles and type parameters
// remain unresolved. Generic containers with a concrete element are supported;
// a type parameter-dependent element must be reviewed explicitly.
func (s *producerSources) shape(t producerType) producerType {
	seen := map[ast.Expr]bool{}
	for t.expr != nil && !seen[t.expr] {
		seen[t.expr] = true
		if s.finding(t) {
			return t
		}
		switch v := ast.Unparen(t.expr).(type) {
		case *ast.StarExpr:
			t.expr = v.X
		case *ast.IndexExpr:
			t.expr = v.X
		case *ast.IndexListExpr:
			t.expr = v.X
		case *ast.Ident, *ast.SelectorExpr:
			d := s.declaration(t.file, t.expr)
			spec, ok := d.node.(*ast.TypeSpec)
			if !ok {
				return producerType{}
			}
			t = producerType{d.file, spec.Type}
		default:
			return t
		}
	}
	return producerType{}
}

func (s *producerSources) valueType(f *ast.File, e ast.Expr, result int, seen map[ast.Expr]bool) producerType {
	e = ast.Unparen(e)
	if e == nil || seen[e] {
		return producerType{}
	}
	seen[e] = true
	defer delete(seen, e)
	switch v := e.(type) {
	case *ast.CompositeLit:
		return s.literalType(f, v)
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			return s.valueType(f, v.X, 0, seen)
		}
	case *ast.StarExpr:
		return s.valueType(f, v.X, 0, seen)
	case *ast.FuncLit:
		return producerType{f, v.Type}
	case *ast.TypeAssertExpr:
		return producerType{f, v.Type}
	case *ast.IndexExpr:
		t := s.shape(s.valueType(f, v.X, 0, seen))
		switch a := t.expr.(type) {
		case *ast.ArrayType:
			return producerType{t.file, a.Elt}
		case *ast.MapType:
			return producerType{t.file, a.Value}
		}
	case *ast.CallExpr:
		if id, ok := v.Fun.(*ast.Ident); ok && id.Obj == nil && (id.Name == "new" || id.Name == "make") && len(v.Args) > 0 {
			return producerType{f, v.Args[0]}
		}
		ft := s.shape(s.valueType(f, v.Fun, 0, seen))
		if fn, ok := ft.expr.(*ast.FuncType); ok && fn.Results != nil {
			for _, field := range fn.Results.List {
				count := max(1, len(field.Names))
				if result < count {
					return producerType{ft.file, field.Type}
				}
				result -= count
			}
		}
	case *ast.Ident:
		d := s.declaration(f, v)
		switch decl := d.node.(type) {
		case *ast.Field:
			return producerType{d.file, decl.Type}
		case *ast.FuncDecl:
			return producerType{d.file, decl.Type}
		case *ast.ValueSpec:
			if decl.Type != nil {
				return producerType{d.file, decl.Type}
			}
			for i, name := range decl.Names {
				if name.Name == v.Name {
					return s.assignedType(d.file, decl.Values, i, seen)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range decl.Lhs {
				if id, ok := ast.Unparen(lhs).(*ast.Ident); ok && id.Obj == v.Obj {
					return s.assignedType(d.file, decl.Rhs, i, seen)
				}
			}
		case *ast.RangeStmt:
			t := s.shape(s.valueType(d.file, decl.X, 0, seen))
			switch a := t.expr.(type) {
			case *ast.ArrayType:
				if id, ok := decl.Value.(*ast.Ident); ok && id.Obj == v.Obj {
					return producerType{t.file, a.Elt}
				}
			case *ast.MapType:
				if id, ok := decl.Key.(*ast.Ident); ok && id.Obj == v.Obj {
					return producerType{t.file, a.Key}
				}
				return producerType{t.file, a.Value}
			}
		}
	case *ast.SelectorExpr:
		if d := s.declaration(f, v); d.node != nil {
			if fn, ok := d.node.(*ast.FuncDecl); ok {
				return producerType{d.file, fn.Type}
			}
		}
		recv := s.valueType(f, v.X, 0, seen)
		if field, _, ok := s.field(recv, v.Sel.Name); ok {
			return field
		}
		// A method signature determines the result without trusting its body.
		for {
			if ptr, ok := recv.expr.(*ast.StarExpr); ok {
				recv.expr = ptr.X
				continue
			}
			break
		}
		d := s.declaration(recv.file, recv.expr)
		if spec, ok := d.node.(*ast.TypeSpec); ok {
			methods := s.files[d.file].methods[spec.Name.Name+"."+v.Sel.Name]
			if len(methods) == 1 {
				return producerType{methods[0].file, methods[0].node.(*ast.FuncDecl).Type}
			}
		}
	}
	return producerType{}
}

func (s *producerSources) assignedType(f *ast.File, values []ast.Expr, i int, seen map[ast.Expr]bool) producerType {
	if len(values) == 1 {
		return s.valueType(f, values[0], i, seen)
	}
	if i < len(values) {
		return s.valueType(f, values[i], 0, seen)
	}
	return producerType{}
}

// field reports the declaring type, so a promoted Finding.Check is guarded
// while an explicit, unrelated Check field that shadows it is not.
func (s *producerSources) field(t producerType, name string) (producerType, bool, bool) {
	level := []producerType{t}
	seen := map[ast.Expr]bool{}
	for len(level) > 0 {
		var next []producerType
		var found producerType
		finding, unknown, matches := false, false, 0
		for _, candidate := range level {
			candidate = s.shape(candidate)
			if candidate.expr == nil || seen[candidate.expr] {
				unknown = true
				continue
			}
			seen[candidate.expr] = true
			if s.finding(candidate) {
				if name == "Check" || name == "SourceIP" || name == "CIDRs" {
					finding = true
					matches++
				}
				continue
			}
			st, ok := candidate.expr.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range st.Fields.List {
				for _, id := range field.Names {
					if id.Name == name {
						found = producerType{candidate.file, field.Type}
						matches++
					}
				}
				if len(field.Names) == 0 {
					ft := producerType{candidate.file, field.Type}
					if embeddedProducerName(field.Type) == name {
						found = ft
						matches++
					}
					next = append(next, ft)
				}
			}
		}
		if matches > 0 || unknown {
			return found, finding, matches == 1 && !unknown
		}
		level = next
	}
	return producerType{}, false, false
}

func embeddedProducerName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.StarExpr:
		return embeddedProducerName(v.X)
	case *ast.IndexExpr:
		return embeddedProducerName(v.X)
	case *ast.IndexListExpr:
		return embeddedProducerName(v.X)
	}
	return ""
}

func (s *producerSources) evidenceTarget(f *ast.File, e ast.Expr) bool {
	for {
		switch v := ast.Unparen(e).(type) {
		case *ast.IndexExpr:
			e = v.X
		case *ast.SelectorExpr:
			return s.evidenceField(f, v)
		default:
			return false
		}
	}
}

func (s *producerSources) evidenceField(f *ast.File, field *ast.SelectorExpr) bool {
	if field.Sel.Name != "Check" && field.Sel.Name != "SourceIP" && field.Sel.Name != "CIDRs" {
		return false
	}
	t := s.valueType(f, field.X, 0, map[ast.Expr]bool{})
	_, finding, known := s.field(t, field.Sel.Name)
	return finding || !known
}

func (s *producerSources) literalType(f *ast.File, cl *ast.CompositeLit) producerType {
	if cl.Type != nil {
		return producerType{f, cl.Type}
	}
	parent := s.parents[cl]
	var key ast.Expr
	if kv, ok := parent.(*ast.KeyValueExpr); ok {
		key = kv.Key
		parent = s.parents[kv]
	}
	outer, ok := parent.(*ast.CompositeLit)
	if !ok {
		return producerType{}
	}
	t := s.shape(s.literalType(f, outer))
	switch v := t.expr.(type) {
	case *ast.ArrayType:
		return producerType{t.file, v.Elt}
	case *ast.MapType:
		if key == cl {
			return producerType{t.file, v.Key}
		}
		return producerType{t.file, v.Value}
	case *ast.StructType:
		if id, ok := key.(*ast.Ident); ok {
			field, _, _ := s.field(t, id.Name)
			return field
		}
	}
	return producerType{}
}

func (s *producerSources) addressLiterals(f *ast.File, decl ast.Decl) []*ast.CompositeLit {
	var out []*ast.CompositeLit
	ast.Inspect(decl, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		t := s.shape(s.literalType(f, cl))
		_, carries := findingCheckField(cl)
		if (t.expr != nil && s.finding(t)) || (t.expr == nil && carries) {
			out = append(out, cl)
		}
		return true
	})
	return out
}
