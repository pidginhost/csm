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
			e = a.analyzeBinding(&s.List[i], e)
		}
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
		e = a.analyzeLoop(s.Body, s.Cond, nil, e)
	case *js.ForInStmt:
		a.evalExpr(s.Value, e)
		e = a.analyzeLoop(s.Body, nil, nil, e)
	case *js.ForOfStmt:
		a.evalExpr(s.Value, e)
		e = a.analyzeLoop(s.Body, nil, nil, e)
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
			e = a.analyzeBinding(&vd.List[i], e)
		}
		return e
	}
	a.evalExpr(init, e)
	return e
}

// analyzeBinding applies a declaration binding: a tainted initializer taints the
// bound variable, a clean or absent initializer clears it (a strong update).
func (a *analysis) analyzeBinding(be *js.BindingElement, e env) env {
	v, ok := be.Binding.(*js.Var)
	if !ok {
		if be.Default != nil {
			a.evalExpr(be.Default, e)
		}
		return e
	}
	cv := canonicalVar(v)
	if be.Default == nil {
		delete(e, cv)
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
	rhs := a.evalExpr(be.Y, e)
	target := ungroupExpr(be.X)
	v, ok := target.(*js.Var)
	if !ok {
		a.evalExpr(target, e)
		return rhs
	}
	cv := canonicalVar(v)
	name := string(cv.Name())
	var nt taintSet
	if be.Op == js.EqToken {
		nt = appendVia(rhs, name)
	} else {
		nt = appendVia(mergeTaint(e[cv], rhs), name)
	}
	if len(nt) == 0 {
		delete(e, cv)
	} else {
		e[cv] = nt
		a.fact()
	}
	return e[cv]
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
		if !a.fact() {
			return merged
		}
		if envEqual(merged, cur) {
			return merged
		}
		cur = merged
	}
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
		a.evalExpr(x.Y, e)
		return nil
	case *js.BinaryExpr:
		if isAssignOp(x.Op) {
			return a.handleAssign(x, e)
		}
		lx := a.evalExpr(x.X, e)
		rx := a.evalExpr(x.Y, e)
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
		return mergeTaint(a.evalExpr(x.X, e), a.evalExpr(x.Y, e))
	case *js.TemplateExpr:
		var ts taintSet
		for i := range x.List {
			ts = mergeTaint(ts, a.evalExpr(x.List[i].Expr, e))
		}
		if x.Tag != nil {
			a.evalExpr(x.Tag, e)
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
		if x.Args != nil {
			for i := range x.Args.List {
				a.evalExpr(x.Args.List[i].Value, e)
			}
		}
		a.evalExpr(x.X, e)
		return nil
	case *js.ArrayExpr:
		for i := range x.List {
			if x.List[i].Value != nil {
				a.evalExpr(x.List[i].Value, e)
			}
		}
		return nil
	case *js.ObjectExpr:
		for i := range x.List {
			a.evalExpr(x.List[i].Value, e)
		}
		return nil
	default:
		return nil
	}
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
