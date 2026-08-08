package jstaint

import (
	"strconv"

	"github.com/tdewolff/parse/v2/js"
)

// srcValue is the abstract value of a keyboard-source read: scalar taint tagged
// with the source occurrence and an empty laundering chain.
func srcValue(id int) value {
	return value{scalar: taintSet{id: taintChain{}}}
}

// analyzeBlock threads the state through a statement list in source order.
func (a *analysis) analyzeBlock(block *js.BlockStmt, st *state) *state {
	if block == nil {
		return st
	}
	for i := range block.List {
		if !a.alive() {
			return st
		}
		st = a.analyzeStmt(block.List[i], st)
	}
	return st
}

func (a *analysis) analyzeStmt(stmt js.IStmt, st *state) *state {
	if !a.alive() {
		return st
	}
	switch s := stmt.(type) {
	case *js.VarDecl:
		for i := range s.List {
			a.analyzeBinding(&s.List[i], st, s.TokenType != js.VarToken)
		}
	case *js.ClassDecl:
		a.evalClass(s, st)
	case *js.ExprStmt:
		a.analyzeExprStmt(s.Value, st)
	case *js.BlockStmt:
		st = a.analyzeBlock(s, st)
	case *js.IfStmt:
		a.evalExpr(s.Cond, st)
		thenSt := a.analyzeStmt(s.Body, st.clone())
		var elseSt *state
		if s.Else != nil {
			elseSt = a.analyzeStmt(s.Else, st.clone())
		} else {
			elseSt = st.clone()
		}
		st = mergeState(thenSt, elseSt)
	case *js.ForStmt:
		a.analyzeInit(s.Init, st)
		st = a.analyzeLoop(s.Body, s.Cond, s.Post, st)
	case *js.WhileStmt:
		st = a.analyzeLoop(s.Body, s.Cond, nil, st)
	case *js.DoWhileStmt:
		st = a.analyzeDoLoop(s.Body, s.Cond, st)
	case *js.ForInStmt:
		a.evalExpr(s.Value, st)
		st = a.analyzeIterationLoop(s.Body, s.Init, value{}, false, st)
	case *js.ForOfStmt:
		iter := a.evalExpr(s.Value, st)
		st = a.analyzeIterationLoop(s.Body, s.Init, iter, true, st)
	case *js.SwitchStmt:
		st = a.analyzeSwitch(s, st)
	case *js.TryStmt:
		st = a.analyzeTry(s, st)
	case *js.ReturnStmt:
		if s.Value != nil {
			a.evalExpr(s.Value, st)
		}
	case *js.ThrowStmt:
		a.evalExpr(s.Value, st)
	case *js.WithStmt:
		a.evalExpr(s.Cond, st)
		bodySt := a.analyzeStmt(s.Body, st.clone())
		st = mergeState(st, bodySt)
	case *js.LabelledStmt:
		st = a.analyzeStmt(s.Value, st)
	case *js.BranchStmt:
		// break/continue: no data effect for this model.
	}
	return st
}

// analyzeInit handles a for-loop initializer, which may be a var declaration or
// an expression.
func (a *analysis) analyzeInit(init js.IExpr, st *state) {
	if init == nil {
		return
	}
	if vd, ok := init.(*js.VarDecl); ok {
		for i := range vd.List {
			a.analyzeBinding(&vd.List[i], st, vd.TokenType != js.VarToken)
		}
		return
	}
	a.evalExpr(init, st)
}

// analyzeBinding applies a declaration binding. A tainted initializer taints the
// bound variable, while a clean initializer is a strong update. An absent lexical
// initializer writes undefined; an absent var initializer is only a declaration.
func (a *analysis) analyzeBinding(be *js.BindingElement, st *state, clearAbsent bool) {
	v, ok := be.Binding.(*js.Var)
	if !ok {
		if be.Default != nil {
			a.evalExpr(be.Default, st)
		}
		a.evalBindingPattern(be.Binding, st)
		return
	}
	cv := canonicalVar(v)
	if be.Default == nil {
		if clearAbsent {
			delete(st.env, cv)
		}
		return
	}
	rhs := a.evalExpr(be.Default, st)
	a.bindVar(st, cv, rhs)
}

// bindVar performs a strong update binding a variable to a value, appending the
// variable name to the laundering chain and preserving aliased allocations.
func (a *analysis) bindVar(st *state, cv *js.Var, rhs value) value {
	nt := value{scalar: appendVia(rhs.scalar, string(cv.Name())), allocs: rhs.allocs, allocOnly: rhs.allocOnly}
	if nt.isEmpty() {
		delete(st.env, cv)
		return value{}
	}
	st.env[cv] = nt
	a.fact()
	return nt
}

func (a *analysis) analyzeExprStmt(expr js.IExpr, st *state) {
	expr = ungroupExpr(expr)
	if be, ok := expr.(*js.BinaryExpr); ok && isAssignOp(be.Op) {
		a.handleAssign(be, st)
		return
	}
	a.evalExpr(expr, st)
}

// handleAssign updates state for target = rhs. A plain assignment is a strong
// update that can clear taint; a compound assignment reads the old value and
// combines it. A logical assignment writes only when its short-circuit condition
// allows, so the write and its right side are may-state.
func (a *analysis) handleAssign(be *js.BinaryExpr, st *state) value {
	target := ungroupExpr(be.X)
	if isLogicalAssignOp(be.Op) {
		return a.handleLogicalAssign(be, target, st)
	}
	switch t := target.(type) {
	case *js.Var:
		cv := canonicalVar(t)
		old := st.env[cv]
		rhs := a.evalExpr(be.Y, st)
		return a.assignVar(st, cv, old, rhs, be.Op)
	case *js.DotExpr, *js.IndexExpr:
		return a.assignMember(be, target, st)
	default:
		a.evalExpr(target, st)
		return a.evalExpr(be.Y, st)
	}
}

func (a *analysis) assignVar(st *state, cv *js.Var, old, rhs value, op js.TokenType) value {
	name := string(cv.Name())
	var nt value
	if op == js.EqToken {
		nt = value{scalar: appendVia(rhs.scalar, name), allocs: rhs.allocs, allocOnly: rhs.allocOnly}
	} else {
		// A compound assignment coerces to a string or number, so the result is a
		// scalar and carries no allocation identity.
		nt = value{scalar: appendVia(mergeTaint(old.scalar, rhs.scalar), name)}
	}
	if nt.isEmpty() {
		delete(st.env, cv)
		return value{}
	}
	st.env[cv] = nt
	a.fact()
	return nt
}

func (a *analysis) assignMember(be *js.BinaryExpr, target js.IExpr, st *state) value {
	recv, key := a.evalMemberTarget(target, st)
	var old value
	if be.Op != js.EqToken {
		// Compound assignment captures the current property value before the RHS
		// runs. The RHS may overwrite the same field.
		old = a.readField(st, recv, key)
	}
	rhs := a.evalExpr(be.Y, st)
	writeVal := rhs
	if be.Op != js.EqToken {
		writeVal = value{scalar: mergeTaint(old.scalar, rhs.scalar)}
	}
	a.writeField(st, recv, key, writeVal)
	return writeVal
}

// handleLogicalAssign models &&=, ||=, and ??=, whose right side and write are
// only reached on the short-circuit path, so both are merged as may-state.
func (a *analysis) handleLogicalAssign(be *js.BinaryExpr, target js.IExpr, st *state) value {
	switch t := target.(type) {
	case *js.Var:
		cv := canonicalVar(t)
		skipped := st.clone()
		taken := st.clone()
		rhs := a.evalExpr(be.Y, taken)
		a.assignVar(taken, cv, taken.env[cv], rhs, js.EqToken)
		st.replaceWith(mergeState(skipped, taken))
		return st.env[cv]
	default:
		recv, key := a.evalMemberTarget(target, st)
		skipped := st.clone()
		taken := st.clone()
		rhs := a.evalExpr(be.Y, taken)
		a.writeField(taken, recv, key, rhs)
		st.replaceWith(mergeState(skipped, taken))
		return a.readField(st, recv, key)
	}
}

// evalMemberTarget evaluates the receiver and key of a member assignment target
// before the right-hand side, and returns the receiver value and field key.
func (a *analysis) evalMemberTarget(target js.IExpr, st *state) (value, fieldKey) {
	switch t := ungroupExpr(target).(type) {
	case *js.DotExpr:
		recv := a.evalExpr(t.X, st)
		return recv, fieldKeyOf(ungroupExpr(t.Y))
	case *js.IndexExpr:
		recv := a.evalExpr(t.X, st)
		a.evalExpr(t.Y, st)
		return recv, fieldKeyOf(ungroupExpr(t.Y))
	}
	return value{}, fieldKey{}
}

// analyzeLoop iterates the body to a fixed point over the loop state.
func (a *analysis) analyzeLoop(body js.IStmt, cond, post js.IExpr, st *state) *state {
	a.loopDepth++
	defer func() { a.loopDepth-- }()
	cur := st.clone()
	for {
		if !a.alive() {
			return cur
		}
		if cond != nil {
			a.evalExpr(cond, cur)
		}
		bodyOut := a.analyzeStmt(body, cur.clone())
		if post != nil {
			a.evalExpr(post, bodyOut)
		}
		merged := mergeState(cur, bodyOut)
		if stateEqual(merged, cur) {
			return merged
		}
		if !a.fact() {
			return merged
		}
		cur = merged
	}
}

// analyzeDoLoop applies the first body execution before merging later iterations,
// because a do-while body always runs at least once.
func (a *analysis) analyzeDoLoop(body js.IStmt, cond js.IExpr, st *state) *state {
	a.loopDepth++
	defer func() { a.loopDepth-- }()
	cur := a.analyzeStmt(body, st.clone())
	if cond != nil {
		a.evalExpr(cond, cur)
	}
	for {
		if !a.alive() {
			return cur
		}
		bodyOut := a.analyzeStmt(body, cur.clone())
		if cond != nil {
			a.evalExpr(cond, bodyOut)
		}
		merged := mergeState(cur, bodyOut)
		if stateEqual(merged, cur) {
			return merged
		}
		if !a.fact() {
			return merged
		}
		cur = merged
	}
}

// analyzeIterationLoop applies the implicit iteration assignment before each body
// execution. The incoming state remains an exit alternative because an iterable
// can be empty.
func (a *analysis) analyzeIterationLoop(
	body js.IStmt,
	init js.IExpr,
	iter value,
	forOf bool,
	st *state,
) *state {
	a.loopDepth++
	defer func() { a.loopDepth-- }()
	cur := st.clone()
	for {
		if !a.alive() {
			return cur
		}
		bodyIn := cur.clone()
		elem := value{}
		if forOf {
			elem = a.iterationElement(bodyIn, iter)
		}
		a.applyIterationBinding(init, elem, bodyIn)
		bodyOut := a.analyzeStmt(body, bodyIn)
		merged := mergeState(cur, bodyOut)
		if stateEqual(merged, cur) {
			return merged
		}
		if !a.fact() {
			return merged
		}
		cur = merged
	}
}

// iterationElement is the value each element of a for-of iterable can carry:
// scalar taint from iterating a tainted string, plus the iterable's element
// field for an array of values.
func (a *analysis) iterationElement(st *state, iter value) value {
	return a.collectArrayElements(st, iter)
}

func (a *analysis) applyIterationBinding(init js.IExpr, elem value, st *state) {
	if decl, ok := init.(*js.VarDecl); ok {
		if len(decl.List) != 0 {
			a.assignIterationVar(decl.List[0].Binding, elem, st)
		}
		return
	}
	if v, ok := ungroupExpr(init).(*js.Var); ok {
		a.bindVar(st, canonicalVar(v), elem)
		return
	}
	target := ungroupExpr(init)
	switch target.(type) {
	case *js.DotExpr, *js.IndexExpr:
		recv, key := a.evalMemberTarget(target, st)
		a.writeField(st, recv, key, elem)
	default:
		a.evalExpr(target, st)
	}
}

func (a *analysis) assignIterationVar(binding js.IBinding, elem value, st *state) {
	if v, ok := binding.(*js.Var); ok {
		a.bindVar(st, canonicalVar(v), elem)
		return
	}
	a.evalBindingPattern(binding, st)
}

// evalBindingPattern evaluates computed property names and nested defaults. This
// phase does not bind values extracted from a destructuring pattern, but the
// pattern's expressions still execute and can contain sinks or scalar writes.
func (a *analysis) evalBindingPattern(binding js.IBinding, st *state) {
	switch b := binding.(type) {
	case *js.BindingArray:
		for i := range b.List {
			a.evalNestedBinding(&b.List[i], st)
		}
		if b.Rest != nil {
			a.evalBindingPattern(b.Rest, st)
		}
	case *js.BindingObject:
		for i := range b.List {
			item := &b.List[i]
			if item.Key != nil {
				a.evalExpr(item.Key.Computed, st)
			}
			a.evalNestedBinding(&item.Value, st)
		}
	}
}

func (a *analysis) evalNestedBinding(be *js.BindingElement, st *state) {
	if be.Default != nil {
		taken := st.clone()
		a.evalExpr(be.Default, taken)
		st.replaceWith(mergeState(st, taken))
	}
	a.evalBindingPattern(be.Binding, st)
}

func (a *analysis) analyzeSwitch(s *js.SwitchStmt, st *state) *state {
	a.evalExpr(s.Init, st)
	out := st.clone()
	var fall *state
	for i := range s.List {
		cl := &s.List[i]
		if cl.Cond != nil {
			a.evalExpr(cl.Cond, st)
		}
		in := st.clone()
		if fall != nil {
			in = mergeState(in, fall)
		}
		for j := range cl.List {
			in = a.analyzeStmt(cl.List[j], in)
		}
		fall = in
		out = mergeState(out, in)
	}
	return out
}

// analyzeTry models that an exception can occur anywhere in the body, so the
// catch clause sees the pre-body state merged with taint the body may have set,
// and the finally clause applies to every outgoing edge.
func (a *analysis) analyzeTry(s *js.TryStmt, st *state) *state {
	bodySt := a.analyzeBlock(s.Body, st.clone())
	merged := bodySt
	if s.Catch != nil {
		catchIn := mergeState(st, bodySt)
		catchSt := a.analyzeBlock(s.Catch, catchIn)
		merged = mergeState(bodySt, catchSt)
	}
	if s.Finally != nil {
		merged = a.analyzeBlock(s.Finally, merged.clone())
	}
	return merged
}

func (a *analysis) evalClass(class *js.ClassDecl, st *state) {
	a.evalExpr(class.Extends, st)
	// Every computed key is evaluated while the class elements are defined. Static
	// fields and blocks initialize only after all keys have been computed.
	for i := range class.List {
		item := &class.List[i]
		if item.Method != nil {
			a.evalExpr(item.Method.Name.Computed, st)
		} else if item.StaticBlock == nil {
			a.evalExpr(item.Name.Computed, st)
		}
	}
	for i := range class.List {
		item := &class.List[i]
		if item.StaticBlock != nil {
			blockSt := a.analyzeBlock(item.StaticBlock, st.clone())
			st.replaceWith(blockSt)
		} else if item.Method == nil && item.Static {
			a.evalExpr(item.Init, st)
		}
	}
}

// evalExpr returns the abstract value of expr and records any sink it reaches. It
// mutates state only through an assignment used as a value or a may-state merge.
func (a *analysis) evalExpr(expr js.IExpr, st *state) value {
	if !a.alive() {
		return value{}
	}
	expr = ungroupExpr(expr)
	switch x := expr.(type) {
	case nil:
		return value{}
	case *js.Var:
		return st.env[canonicalVar(x)]
	case *js.LiteralExpr:
		return value{}
	case *js.DotExpr:
		if occ, ok := a.sources[expr]; ok {
			return srcValue(occ.id)
		}
		base := a.evalExpr(x.X, st)
		name, ok := staticStringOrIdent(ungroupExpr(x.Y))
		if !ok {
			return value{}
		}
		return a.readField(st, base, fieldKey{kind: fieldNamed, name: name})
	case *js.IndexExpr:
		if occ, ok := a.sources[expr]; ok {
			return srcValue(occ.id)
		}
		base := a.evalExpr(x.X, st)
		key := a.evalReadIndexKey(x, st)
		return a.readField(st, base, key)
	case *js.BinaryExpr:
		if isAssignOp(x.Op) {
			return a.handleAssign(x, st)
		}
		lx := a.evalExpr(x.X, st)
		var rx value
		if isLogicalOp(x.Op) {
			skipped := st.clone()
			taken := st.clone()
			rx = a.evalExpr(x.Y, taken)
			st.replaceWith(mergeState(skipped, taken))
		} else {
			rx = a.evalExpr(x.Y, st)
		}
		if binaryOpPropagates(x.Op) {
			if isLogicalOp(x.Op) {
				// ||, &&, and ?? return one operand value, so both allocations and
				// scalars can flow through.
				return mergeValue(lx, rx)
			}
			return value{scalar: mergeTaint(lx.scalar, rx.scalar)}
		}
		return value{}
	case *js.UnaryExpr:
		return a.evalUnary(x, st)
	case *js.CondExpr:
		a.evalExpr(x.Cond, st)
		thenSt := st.clone()
		elseSt := st.clone()
		thenVal := a.evalExpr(x.X, thenSt)
		elseVal := a.evalExpr(x.Y, elseSt)
		st.replaceWith(mergeState(thenSt, elseSt))
		return mergeValue(thenVal, elseVal)
	case *js.TemplateExpr:
		return a.evalTemplate(x, st)
	case *js.CommaExpr:
		var last value
		for i := range x.List {
			last = a.evalExpr(x.List[i], st)
		}
		return last
	case *js.CallExpr:
		return a.evalCall(x, st)
	case *js.NewExpr:
		return a.evalNew(x, st)
	case *js.ArrayExpr:
		return a.evalArray(x, st)
	case *js.ObjectExpr:
		return a.evalObject(x, st)
	case *js.ClassDecl:
		a.evalClass(x, st)
		return value{}
	default:
		return value{}
	}
}

func (a *analysis) evalUnary(x *js.UnaryExpr, st *state) value {
	if x.Op == js.DeleteToken {
		a.evalDelete(x.X, st)
		return value{}
	}
	if isUpdateOp(x.Op) {
		return a.evalUpdate(x.X, st)
	}
	xt := a.evalExpr(x.X, st)
	if x.Op == js.AwaitToken {
		return xt
	}
	if unaryOpPropagates(x.Op) {
		return value{scalar: xt.scalar}
	}
	return value{}
}

func (a *analysis) evalDelete(target js.IExpr, st *state) {
	target = ungroupExpr(target)
	switch target.(type) {
	case *js.DotExpr, *js.IndexExpr:
		if optionalChainMaySkip(target) {
			skipped := st.clone()
			taken := st.clone()
			recv, key := a.evalMemberTarget(target, taken)
			a.deleteField(taken, recv, key)
			st.replaceWith(mergeState(skipped, taken))
			return
		}
		recv, key := a.evalMemberTarget(target, st)
		a.deleteField(st, recv, key)
	default:
		a.evalExpr(target, st)
	}
}

func (a *analysis) evalUpdate(target js.IExpr, st *state) value {
	target = ungroupExpr(target)
	switch t := target.(type) {
	case *js.Var:
		cv := canonicalVar(t)
		old := st.env[cv]
		return a.assignVar(st, cv, old, value{}, js.AddEqToken)
	case *js.DotExpr, *js.IndexExpr:
		recv, key := a.evalMemberTarget(target, st)
		old := a.readField(st, recv, key)
		updated := value{scalar: old.scalar}
		a.writeField(st, recv, key, updated)
		return updated
	default:
		old := a.evalExpr(target, st)
		return value{scalar: old.scalar}
	}
}

func isUpdateOp(op js.TokenType) bool {
	switch op {
	case js.PreIncrToken, js.PreDecrToken, js.PostIncrToken, js.PostDecrToken:
		return true
	default:
		return false
	}
}

func (a *analysis) evalTemplate(x *js.TemplateExpr, st *state) value {
	if x.Tag != nil {
		a.evalExpr(x.Tag, st)
		valuesSt := st
		if x.Optional {
			valuesSt = st.clone()
		}
		for i := range x.List {
			a.evalExpr(x.List[i].Expr, valuesSt)
		}
		if x.Optional {
			st.replaceWith(mergeState(st, valuesSt))
		}
		// A tag function's return value is not modeled, so the result is clean.
		return value{}
	}
	var ts taintSet
	for i := range x.List {
		ts = mergeTaint(ts, a.evalExpr(x.List[i].Expr, st).scalar)
	}
	return value{scalar: ts}
}

// evalReadIndexKey evaluates a read index expression, honoring optional-chain
// short-circuit for its side effects, and returns the field key it selects.
func (a *analysis) evalReadIndexKey(x *js.IndexExpr, st *state) fieldKey {
	if x.Optional || optionalChainMaySkip(x.X) {
		skipped := st.clone()
		taken := st.clone()
		a.evalExpr(x.Y, taken)
		st.replaceWith(mergeState(skipped, taken))
	} else {
		a.evalExpr(x.Y, st)
	}
	return fieldKeyOf(ungroupExpr(x.Y))
}

func (a *analysis) evalNew(x *js.NewExpr, st *state) value {
	isArray := a.isGlobalCallee(x.X, "Array")
	a.evalExpr(x.X, st)
	var args []value
	if x.Args != nil {
		args = make([]value, len(x.Args.List))
		for i := range x.Args.List {
			args[i] = a.evalExpr(x.Args.List[i].Value, st)
		}
	}
	site, ok := a.sites[x]
	if !ok {
		return value{}
	}
	if !isArray {
		return a.allocate(st, site, a.loopDepth > 0)
	}
	a.promoteCurrent(st, site)
	fresh := &object{array: true}
	if len(args) != 1 || !isNumericLiteralExpr(x.Args.List[0].Value) {
		for i := range args {
			fresh.setNamed(strconv.Itoa(i), args[i], true)
			a.fact()
		}
	}
	return a.installLiteral(st, site, a.loopDepth > 0, fresh)
}

func isNumericLiteralExpr(expr js.IExpr) bool {
	_, ok := numericPropertyNameOf(expr)
	return ok
}

func (a *analysis) evalArray(x *js.ArrayExpr, st *state) value {
	site, ok := a.sites[x]
	if !ok {
		for i := range x.List {
			if x.List[i].Value != nil {
				a.evalExpr(x.List[i].Value, st)
			}
		}
		return value{}
	}
	a.promoteCurrent(st, site)
	fresh := &object{array: true}
	unknownIndex := false
	for i := range x.List {
		el := &x.List[i]
		if el.Value == nil {
			continue
		}
		ev := a.evalExpr(el.Value, st)
		if el.Spread {
			fresh.weakElem(a.spreadElements(st, ev), false)
			unknownIndex = true
			a.fact()
			continue
		}
		if unknownIndex {
			fresh.weakElem(ev, true)
		} else {
			fresh.setNamed(strconv.Itoa(i), ev, true)
		}
		a.fact()
	}
	return a.installLiteral(st, site, a.loopDepth > 0, fresh)
}

func (a *analysis) evalObject(x *js.ObjectExpr, st *state) value {
	site, ok := a.sites[x]
	if !ok {
		a.evalObjectSideEffects(x, st)
		return value{}
	}
	// A literal's properties are evaluated into one fresh runtime object. Only
	// after the final property is known is that object merged into a loop summary.
	a.promoteCurrent(st, site)
	fresh := &object{}
	for i := range x.List {
		p := &x.List[i]
		if p.Spread {
			sv := a.evalExpr(p.Value, st)
			a.spreadInto(st, fresh, sv)
			continue
		}
		if p.Name != nil && p.Name.Computed != nil {
			a.evalExpr(p.Name.Computed, st)
		}
		pv := a.evalExpr(p.Value, st)
		if p.Init != nil {
			a.evalExpr(p.Init, st)
		}
		key := fieldKey{kind: fieldWild}
		if p.Name != nil {
			if p.Name.IsComputed() {
				key = fieldKeyOf(ungroupExpr(p.Name.Computed))
			} else {
				key = fieldKeyOf(&p.Name.Literal)
			}
		}
		switch key.kind {
		case fieldNamed:
			fresh.setNamed(key.name, pv, true)
		case fieldElem:
			if key.name != "" {
				fresh.setNamed(key.name, pv, true)
			} else {
				fresh.weakElem(pv, true)
			}
		default:
			fresh.writeWild(pv, true)
		}
		a.fact()
	}
	return a.installLiteral(st, site, a.loopDepth > 0, fresh)
}

// evalObjectSideEffects evaluates an object literal's expressions without
// recording fields, used only when the literal had no allocation site assigned.
func (a *analysis) evalObjectSideEffects(x *js.ObjectExpr, st *state) {
	for i := range x.List {
		p := &x.List[i]
		if p.Name != nil && p.Name.Computed != nil {
			a.evalExpr(p.Name.Computed, st)
		}
		a.evalExpr(p.Value, st)
		if p.Init != nil {
			a.evalExpr(p.Init, st)
		}
	}
}

// spreadElements collapses a spread source's element taint into one value for
// insertion into the target array element field.
func (a *analysis) spreadElements(st *state, src value) value {
	return a.collectArrayElements(st, src)
}

func (a *analysis) collectArrayElements(st *state, src value) value {
	var out value
	have := false
	if len(src.scalar) != 0 {
		out, have = mergePresentValue(out, have, value{scalar: src.scalar})
	}
	for id := range src.allocs {
		o := st.heap[id]
		if o == nil || !o.array {
			continue
		}
		for name, fv := range o.fields {
			if isArrayIndexName(name) {
				out, have = mergePresentValue(out, have, fv)
			}
		}
		if o.elemMay {
			out, have = mergePresentValue(out, have, o.elem)
		}
		if o.wildMay {
			out, have = mergePresentValue(out, have, o.wild)
		}
	}
	if !have {
		return value{}
	}
	if !src.allocOnly {
		out.allocOnly = false
	}
	return out
}

// spreadInto copies a spread source onto a fresh object literal. A named field
// present on every possible source definitely overwrites the earlier property;
// partial and unresolved fields remain weak updates.
func (a *analysis) spreadInto(st *state, dst *object, src value) {
	fields := map[string]value{}
	definite := map[string]int{}
	elemDefinite := 0
	wildDefinite := 0
	var elem, wild, wildReq value
	elemMay := false
	wildMay := false
	wildReqSeen := false
	for sid := range src.allocs {
		so := st.heap[sid]
		if so == nil {
			continue
		}
		for k, fv := range so.fields {
			if old, ok := fields[k]; ok {
				fields[k] = mergeValue(old, fv)
			} else {
				fields[k] = fv
			}
			if so.must[k] {
				definite[k]++
			}
		}
		if so.elemMay {
			elem, elemMay = mergePresentValue(elem, elemMay, so.elem)
		}
		if so.wildMay {
			wild, wildMay = mergePresentValue(wild, wildMay, so.wild)
		}
		if so.elemMust {
			elemDefinite++
		}
		if so.wildMust {
			wildDefinite++
			if wildReqSeen {
				wildReq = mergeValue(wildReq, so.wildReq)
			} else {
				wildReq = so.wildReq
				wildReqSeen = true
			}
		}
	}
	// A scalar spread contributes character properties at numeric keys.
	if len(src.scalar) != 0 {
		elem, elemMay = mergePresentValue(elem, elemMay, value{scalar: src.scalar})
	}
	allSources := src.allocOnly && len(src.allocs) != 0
	if wildMay {
		dst.writeWild(wild, false)
	}
	if allSources && wildDefinite == len(src.allocs) {
		dst.wildMust = true
		dst.wildReq = wildReq
	}
	for k, fv := range fields {
		dst.setNamed(k, fv, allSources && definite[k] == len(src.allocs))
	}
	if elemMay {
		dst.weakElem(elem, allSources && elemDefinite == len(src.allocs))
	}
	a.fact()
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
