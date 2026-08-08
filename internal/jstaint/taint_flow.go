package jstaint

import "github.com/tdewolff/parse/v2/js"

// analyzeBlock threads the environment through a statement list in source order.
func (a *analysis) analyzeBlock(block *js.BlockStmt, e env) env {
	if block == nil {
		return e
	}
	for i := range block.List {
		if !a.alive() {
			return e
		}
		e = a.analyzeStmt(block.List[i], e)
	}
	return e
}

func (a *analysis) analyzeStmt(stmt js.IStmt, e env) env {
	if !a.alive() {
		return e
	}
	switch s := stmt.(type) {
	case *js.VarDecl:
		for i := range s.List {
			e = a.analyzeBinding(&s.List[i], e, s.TokenType != js.VarToken)
		}
	case *js.ClassDecl:
		a.evalClass(s, e)
	case *js.ExprStmt:
		a.analyzeExprStmt(s.Value, e)
	case *js.BlockStmt:
		e = a.analyzeBlock(s, e)
	case *js.IfStmt:
		a.evalExpr(s.Cond, e)
		thenE := a.analyzeStmt(s.Body, copyEnv(e))
		var elseE env
		if s.Else != nil {
			elseE = a.analyzeStmt(s.Else, copyEnv(e))
		} else {
			elseE = copyEnv(e)
		}
		e = mergeEnv(thenE, elseE)
	case *js.ForStmt:
		e = a.analyzeInit(s.Init, e)
		e = a.analyzeLoop(s.Body, s.Cond, s.Post, e)
	case *js.WhileStmt:
		e = a.analyzeLoop(s.Body, s.Cond, nil, e)
	case *js.DoWhileStmt:
		e = a.analyzeDoLoop(s.Body, s.Cond, e)
	case *js.ForInStmt:
		a.evalExpr(s.Value, e)
		e = a.analyzeIterationLoop(s.Body, s.Init, nil, e)
	case *js.ForOfStmt:
		iterTaint := a.evalExpr(s.Value, e)
		e = a.analyzeIterationLoop(s.Body, s.Init, iterTaint, e)
	case *js.SwitchStmt:
		e = a.analyzeSwitch(s, e)
	case *js.TryStmt:
		e = a.analyzeTry(s, e)
	case *js.ReturnStmt:
		if s.Value != nil {
			a.evalExpr(s.Value, e)
		}
	case *js.ThrowStmt:
		a.evalExpr(s.Value, e)
	case *js.WithStmt:
		a.evalExpr(s.Cond, e)
		bodyE := a.analyzeStmt(s.Body, copyEnv(e))
		e = mergeEnv(e, bodyE)
	case *js.LabelledStmt:
		e = a.analyzeStmt(s.Value, e)
	case *js.BranchStmt:
		// break/continue: no data effect for the scalar model.
	}
	return e
}

// analyzeInit handles a for-loop initializer, which may be a var declaration or
// an expression.
func (a *analysis) analyzeInit(init js.IExpr, e env) env {
	if init == nil {
		return e
	}
	if vd, ok := init.(*js.VarDecl); ok {
		for i := range vd.List {
			e = a.analyzeBinding(&vd.List[i], e, vd.TokenType != js.VarToken)
		}
		return e
	}
	a.evalExpr(init, e)
	return e
}

// analyzeBinding applies a declaration binding. A tainted initializer taints the
// bound variable, while a clean initializer is a strong update. An absent lexical
// initializer writes undefined; an absent var initializer is only a declaration.
func (a *analysis) analyzeBinding(be *js.BindingElement, e env, clearAbsent bool) env {
	v, ok := be.Binding.(*js.Var)
	if !ok {
		if be.Default != nil {
			a.evalExpr(be.Default, e)
		}
		a.evalBindingPattern(be.Binding, e)
		return e
	}
	cv := canonicalVar(v)
	if be.Default == nil {
		if clearAbsent {
			delete(e, cv)
		}
		return e
	}
	rhs := a.evalExpr(be.Default, e)
	nt := appendVia(rhs, string(cv.Name()))
	if len(nt) == 0 {
		delete(e, cv)
	} else {
		e[cv] = nt
		a.fact()
	}
	return e
}

func (a *analysis) analyzeExprStmt(expr js.IExpr, e env) {
	expr = ungroupExpr(expr)
	if be, ok := expr.(*js.BinaryExpr); ok && isAssignOp(be.Op) {
		a.handleAssign(be, e)
		return
	}
	a.evalExpr(expr, e)
}

// handleAssign updates env for target = rhs. A plain assignment is a strong
// update that can clear taint; a compound assignment reads the old value and
// combines it.
func (a *analysis) handleAssign(be *js.BinaryExpr, e env) taintSet {
	target := ungroupExpr(be.X)
	v, ok := target.(*js.Var)
	if isLogicalAssignOp(be.Op) {
		if ok {
			return a.handleLogicalVarAssign(v, be.Y, e)
		}
		lhs := a.evalAssignmentTarget(target, e, true)
		skipped := copyEnv(e)
		taken := copyEnv(e)
		rhs := a.evalExpr(be.Y, taken)
		replaceEnv(e, mergeEnv(skipped, taken))
		return mergeTaint(lhs, rhs)
	}
	if !ok {
		lhs := a.evalAssignmentTarget(target, e, be.Op != js.EqToken)
		rhs := a.evalExpr(be.Y, e)
		if be.Op != js.EqToken {
			return mergeTaint(lhs, rhs)
		}
		return rhs
	}
	cv := canonicalVar(v)
	name := string(cv.Name())
	old := e[cv]
	rhs := a.evalExpr(be.Y, e)
	var nt taintSet
	if be.Op == js.EqToken {
		nt = appendVia(rhs, name)
	} else {
		nt = appendVia(mergeTaint(old, rhs), name)
	}
	if len(nt) == 0 {
		delete(e, cv)
	} else {
		e[cv] = nt
		a.fact()
	}
	return e[cv]
}

func (a *analysis) handleLogicalVarAssign(v *js.Var, rhsExpr js.IExpr, e env) taintSet {
	cv := canonicalVar(v)
	skipped := copyEnv(e)
	taken := copyEnv(e)
	rhs := a.evalExpr(rhsExpr, taken)
	nt := appendVia(rhs, string(cv.Name()))
	if len(nt) == 0 {
		delete(taken, cv)
	} else {
		taken[cv] = nt
		a.fact()
	}
	replaceEnv(e, mergeEnv(skipped, taken))
	return e[cv]
}

// evalAssignmentTarget evaluates the reference-producing parts of an assignment
// target before the right-hand side. Compound assignments also read the target's
// current value.
func (a *analysis) evalAssignmentTarget(target js.IExpr, e env, read bool) taintSet {
	if read {
		return a.evalExpr(target, e)
	}
	switch x := target.(type) {
	case *js.DotExpr:
		a.evalExpr(x.X, e)
	case *js.IndexExpr:
		a.evalExpr(x.X, e)
		a.evalExpr(x.Y, e)
	default:
		a.evalExpr(target, e)
	}
	return nil
}

// analyzeLoop iterates the body to a fixed point over its local environment.
func (a *analysis) analyzeLoop(body js.IStmt, cond, post js.IExpr, e env) env {
	cur := copyEnv(e)
	for {
		if !a.alive() {
			return cur
		}
		if cond != nil {
			a.evalExpr(cond, cur)
		}
		bodyOut := a.analyzeStmt(body, copyEnv(cur))
		if post != nil {
			a.evalExpr(post, bodyOut)
		}
		merged := mergeEnv(cur, bodyOut)
		if envEqual(merged, cur) {
			return merged
		}
		if !a.fact() {
			return merged
		}
		cur = merged
	}
}

// analyzeDoLoop applies the first body execution as a strong update before
// merging later iterations. A do-while body always runs at least once.
func (a *analysis) analyzeDoLoop(body js.IStmt, cond js.IExpr, e env) env {
	cur := a.analyzeStmt(body, copyEnv(e))
	if cond != nil {
		a.evalExpr(cond, cur)
	}
	for {
		if !a.alive() {
			return cur
		}
		bodyOut := a.analyzeStmt(body, copyEnv(cur))
		if cond != nil {
			a.evalExpr(cond, bodyOut)
		}
		merged := mergeEnv(cur, bodyOut)
		if envEqual(merged, cur) {
			return merged
		}
		if !a.fact() {
			return merged
		}
		cur = merged
	}
}

// analyzeIterationLoop applies the implicit iteration assignment before each
// body execution. The incoming state remains an exit alternative because an
// iterable can be empty.
func (a *analysis) analyzeIterationLoop(body js.IStmt, init js.IExpr, iterTaint taintSet, e env) env {
	cur := copyEnv(e)
	for {
		if !a.alive() {
			return cur
		}
		bodyIn := copyEnv(cur)
		a.applyIterationBinding(init, iterTaint, bodyIn)
		bodyOut := a.analyzeStmt(body, bodyIn)
		merged := mergeEnv(cur, bodyOut)
		if envEqual(merged, cur) {
			return merged
		}
		if !a.fact() {
			return merged
		}
		cur = merged
	}
}

func (a *analysis) applyIterationBinding(init js.IExpr, ts taintSet, e env) {
	if decl, ok := init.(*js.VarDecl); ok {
		if len(decl.List) != 0 {
			a.assignIterationVar(decl.List[0].Binding, ts, e)
		}
		return
	}
	if v, ok := ungroupExpr(init).(*js.Var); ok {
		a.assignVarTaint(v, ts, e)
		return
	}
	a.evalAssignmentTarget(ungroupExpr(init), e, false)
}

func (a *analysis) assignIterationVar(binding js.IBinding, ts taintSet, e env) {
	if v, ok := binding.(*js.Var); ok {
		a.assignVarTaint(v, ts, e)
		return
	}
	a.evalBindingPattern(binding, e)
}

func (a *analysis) assignVarTaint(v *js.Var, ts taintSet, e env) {
	cv := canonicalVar(v)
	nt := appendVia(ts, string(cv.Name()))
	if len(nt) == 0 {
		delete(e, cv)
		return
	}
	e[cv] = nt
	a.fact()
}

// evalBindingPattern evaluates computed property names and nested defaults. The
// scalar-only phase does not bind values extracted from objects or arrays, but
// these expressions still execute and can contain sinks or scalar writes.
func (a *analysis) evalBindingPattern(binding js.IBinding, e env) {
	switch b := binding.(type) {
	case *js.BindingArray:
		for i := range b.List {
			a.evalNestedBinding(&b.List[i], e)
		}
		if b.Rest != nil {
			a.evalBindingPattern(b.Rest, e)
		}
	case *js.BindingObject:
		for i := range b.List {
			item := &b.List[i]
			if item.Key != nil {
				a.evalExpr(item.Key.Computed, e)
			}
			a.evalNestedBinding(&item.Value, e)
		}
	}
}

func (a *analysis) evalNestedBinding(be *js.BindingElement, e env) {
	if be.Default != nil {
		taken := copyEnv(e)
		a.evalExpr(be.Default, taken)
		replaceEnv(e, mergeEnv(e, taken))
	}
	a.evalBindingPattern(be.Binding, e)
}

func (a *analysis) analyzeSwitch(s *js.SwitchStmt, e env) env {
	a.evalExpr(s.Init, e)
	out := copyEnv(e)
	var fall env
	for i := range s.List {
		cl := &s.List[i]
		if cl.Cond != nil {
			a.evalExpr(cl.Cond, e)
		}
		in := copyEnv(e)
		if fall != nil {
			in = mergeEnv(in, fall)
		}
		for j := range cl.List {
			in = a.analyzeStmt(cl.List[j], in)
		}
		fall = in
		out = mergeEnv(out, in)
	}
	return out
}

// analyzeTry models that an exception can occur anywhere in the body, so the
// catch clause sees the pre-body state merged with taint the body may have set,
// and the finally clause applies to every outgoing edge.
func (a *analysis) analyzeTry(s *js.TryStmt, e env) env {
	bodyE := a.analyzeBlock(s.Body, copyEnv(e))
	merged := bodyE
	if s.Catch != nil {
		catchIn := mergeEnv(e, bodyE)
		catchE := a.analyzeBlock(s.Catch, catchIn)
		merged = mergeEnv(bodyE, catchE)
	}
	if s.Finally != nil {
		merged = a.analyzeBlock(s.Finally, copyEnv(merged))
	}
	return merged
}

func (a *analysis) evalClass(class *js.ClassDecl, e env) {
	a.evalExpr(class.Extends, e)
	// Every computed key is evaluated while the class elements are defined.
	// Static fields and blocks initialize only after all keys have been computed.
	for i := range class.List {
		item := &class.List[i]
		if item.Method != nil {
			a.evalExpr(item.Method.Name.Computed, e)
		} else if item.StaticBlock == nil {
			a.evalExpr(item.Name.Computed, e)
		}
	}
	for i := range class.List {
		item := &class.List[i]
		if item.StaticBlock != nil {
			blockOut := a.analyzeBlock(item.StaticBlock, copyEnv(e))
			replaceEnv(e, blockOut)
		} else if item.Method == nil && item.Static {
			a.evalExpr(item.Init, e)
		}
	}
}

// evalExpr returns the taint of expr and records any sink it reaches. It never
// mutates env except through an assignment used as a value.
func (a *analysis) evalExpr(expr js.IExpr, e env) taintSet {
	if !a.alive() {
		return nil
	}
	expr = ungroupExpr(expr)
	switch x := expr.(type) {
	case nil:
		return nil
	case *js.Var:
		return e[canonicalVar(x)]
	case *js.LiteralExpr:
		return nil
	case *js.DotExpr:
		if occ, ok := a.sources[expr]; ok {
			return taintSet{occ.id: taintChain{}}
		}
		a.evalExpr(x.X, e)
		return nil
	case *js.IndexExpr:
		if occ, ok := a.sources[expr]; ok {
			return taintSet{occ.id: taintChain{}}
		}
		a.evalExpr(x.X, e)
		if x.Optional || optionalChainMaySkip(x.X) {
			skipped := copyEnv(e)
			taken := copyEnv(e)
			a.evalExpr(x.Y, taken)
			replaceEnv(e, mergeEnv(skipped, taken))
		} else {
			a.evalExpr(x.Y, e)
		}
		return nil
	case *js.BinaryExpr:
		if isAssignOp(x.Op) {
			return a.handleAssign(x, e)
		}
		lx := a.evalExpr(x.X, e)
		var rx taintSet
		if isLogicalOp(x.Op) {
			skipped := copyEnv(e)
			taken := copyEnv(e)
			rx = a.evalExpr(x.Y, taken)
			replaceEnv(e, mergeEnv(skipped, taken))
		} else {
			rx = a.evalExpr(x.Y, e)
		}
		if binaryOpPropagates(x.Op) {
			return mergeTaint(lx, rx)
		}
		return nil
	case *js.UnaryExpr:
		xt := a.evalExpr(x.X, e)
		if unaryOpPropagates(x.Op) {
			return xt
		}
		return nil
	case *js.CondExpr:
		a.evalExpr(x.Cond, e)
		thenE := copyEnv(e)
		elseE := copyEnv(e)
		thenTaint := a.evalExpr(x.X, thenE)
		elseTaint := a.evalExpr(x.Y, elseE)
		replaceEnv(e, mergeEnv(thenE, elseE))
		return mergeTaint(thenTaint, elseTaint)
	case *js.TemplateExpr:
		if x.Tag != nil {
			a.evalExpr(x.Tag, e)
			valuesE := e
			if x.Optional {
				valuesE = copyEnv(e)
			}
			for i := range x.List {
				a.evalExpr(x.List[i].Expr, valuesE)
			}
			if x.Optional {
				replaceEnv(e, mergeEnv(e, valuesE))
			}
			return nil
		}
		var ts taintSet
		for i := range x.List {
			ts = mergeTaint(ts, a.evalExpr(x.List[i].Expr, e))
		}
		return ts
	case *js.CommaExpr:
		var last taintSet
		for i := range x.List {
			last = a.evalExpr(x.List[i], e)
		}
		return last
	case *js.CallExpr:
		return a.evalCall(x, e)
	case *js.NewExpr:
		a.evalExpr(x.X, e)
		if x.Args != nil {
			for i := range x.Args.List {
				a.evalExpr(x.Args.List[i].Value, e)
			}
		}
		return nil
	case *js.ArrayExpr:
		for i := range x.List {
			if x.List[i].Value != nil {
				a.evalExpr(x.List[i].Value, e)
			}
		}
		return nil
	case *js.ObjectExpr:
		a.evalObjectProperties(x, e, nil)
		return nil
	case *js.ClassDecl:
		a.evalClass(x, e)
		return nil
	default:
		return nil
	}
}

func (a *analysis) evalObjectProperties(obj *js.ObjectExpr, e env, visit func(string, taintSet)) {
	for i := range obj.List {
		p := &obj.List[i]
		if p.Name != nil && p.Name.Computed != nil {
			a.evalExpr(p.Name.Computed, e)
		}
		ts := a.evalExpr(p.Value, e)
		if p.Init != nil {
			a.evalExpr(p.Init, e)
		}
		if visit == nil || p.Name == nil || p.Name.IsComputed() {
			continue
		}
		if name, ok := staticStringOrIdent(&p.Name.Literal); ok {
			visit(name, ts)
		}
	}
}

func isLogicalOp(op js.TokenType) bool {
	return op == js.AndToken || op == js.OrToken || op == js.NullishToken
}

func isLogicalAssignOp(op js.TokenType) bool {
	return op == js.AndEqToken || op == js.OrEqToken || op == js.NullishEqToken
}

func isAssignOp(op js.TokenType) bool {
	switch op {
	case js.EqToken, js.AddEqToken, js.SubEqToken, js.MulEqToken, js.DivEqToken,
		js.ModEqToken, js.ExpEqToken, js.LtLtEqToken, js.GtGtEqToken, js.GtGtGtEqToken,
		js.BitAndEqToken, js.BitOrEqToken, js.BitXorEqToken,
		js.AndEqToken, js.OrEqToken, js.NullishEqToken:
		return true
	default:
		return false
	}
}
