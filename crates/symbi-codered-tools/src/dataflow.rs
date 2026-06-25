//! Tree-sitter-driven dataflow extraction (Python, Rust, TypeScript/JavaScript).
//!
//! Walks a parsed AST and emits [`DataflowEdge`] rows for:
//!   - `assign`:    `x = y`        → edge from `y` to `x` (`edge_kind="assign"`)
//!   - `subscript`: `x = obj[k]`   → edge from `obj` to `x` (`edge_kind="subscript"`)
//!   - `call_arg`:  `f(arg)`       → edge from `arg` to callee (`edge_kind="call_arg"`)
//!   - `return`:    `return x`     → edge from `x` to `<file>:<fn>:<return>`
//!
//! Symbol naming convention: `<file>:<enclosing_function>:<identifier>`. If no
//! enclosing function is in scope, the middle segment is omitted (e.g.
//! `app/__init__.py::flask_app` for module-level).

use symbi_codered_core::db::DataflowEdge;
use tree_sitter::{Node, Tree, TreeCursor};
use uuid::Uuid;

/// Walk a parsed Python AST and emit dataflow edges for assignments and
/// subscript right-hand sides.
pub fn extract_python_edges(
    tree: &Tree,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
) -> Vec<DataflowEdge> {
    let mut edges = Vec::new();
    let root = tree.root_node();
    walk(
        &mut root.walk(),
        source,
        engagement_id,
        file_path,
        None,
        &mut edges,
    );
    edges
}

fn walk(
    cursor: &mut TreeCursor,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    enclosing_fn: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let node = cursor.node();
    let kind = node.kind();

    // Track function context so symbol names can include `<fn>:`.
    let new_fn: Option<String> = if kind == "function_definition" {
        node.child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok().map(String::from))
    } else {
        None
    };
    let fn_ctx_owned = new_fn;
    let fn_ctx = fn_ctx_owned.as_deref().or(enclosing_fn);

    match kind {
        "assignment" | "augmented_assignment" => {
            emit_assignment(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "call" => {
            emit_call_arg(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "return_statement" => {
            emit_return(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            walk(cursor, source, engagement_id, file_path, fn_ctx, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn emit_assignment(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let left = node.child_by_field_name("left");
    let right = node.child_by_field_name("right");
    let (Some(left), Some(right)) = (left, right) else {
        return;
    };

    let line = (left.start_position().row + 1) as i64;
    let to = qualify(file_path, fn_ctx, &node_text(&left, source));

    // Walk the right-hand side looking for identifiers and subscripts.
    // We deliberately do NOT descend into `subscript` children — the subscript
    // node itself is the data source, and we want a single edge per subscript
    // RHS rather than one per identifier inside the brackets.
    let mut stack = vec![right];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" => {
                let from = qualify(file_path, fn_ctx, &node_text(&n, source));
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.clone(),
                        edge_kind: "assign".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "subscript" => {
                // `obj[k]` — record an edge from obj.
                if let Some(obj) = n.child_by_field_name("value") {
                    let from = qualify(file_path, fn_ctx, &node_text(&obj, source));
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.clone(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            _ => {
                let mut c = n.walk();
                if c.goto_first_child() {
                    loop {
                        stack.push(c.node());
                        if !c.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn emit_call_arg(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    // `callee(arg1, arg2)` — emit an edge from each arg identifier to the
    // callee's qualified name. We use the callee text directly since we don't
    // yet resolve cross-module bindings.
    //
    // We only inspect immediate children of the `arguments` list (depth 1).
    // Nested calls inside the args list are handled separately by the outer
    // `walk()` recursion, so this loop does not descend into them.
    let Some(callee) = node.child_by_field_name("function") else {
        return;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let callee_q = qualify(file_path, fn_ctx, &node_text(&callee, source));

    let mut c = args.walk();
    if c.goto_first_child() {
        loop {
            let a = c.node();
            if a.kind() == "identifier" {
                out.push(DataflowEdge {
                    engagement_id,
                    from_symbol: qualify(file_path, fn_ctx, &node_text(&a, source)),
                    to_symbol: callee_q.clone(),
                    edge_kind: "call_arg".into(),
                    file_path: file_path.into(),
                    line,
                });
            }
            if !c.goto_next_sibling() {
                break;
            }
        }
    }
}

fn emit_return(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(fname) = fn_ctx else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let mut c = node.walk();
    if !c.goto_first_child() {
        return;
    }
    loop {
        let n = c.node();
        if n.kind() == "identifier" {
            out.push(DataflowEdge {
                engagement_id,
                from_symbol: qualify(file_path, fn_ctx, &node_text(&n, source)),
                to_symbol: format!("{file_path}:{fname}:<return>"),
                edge_kind: "return".into(),
                file_path: file_path.into(),
                line,
            });
        }
        if !c.goto_next_sibling() {
            break;
        }
    }
}

fn qualify(file_path: &str, fn_ctx: Option<&str>, ident: &str) -> String {
    match fn_ctx {
        Some(fname) => format!("{file_path}:{fname}:{ident}"),
        None => format!("{file_path}::{ident}"),
    }
}

fn node_text(node: &Node, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_string()
}

// ---------------------------------------------------------------------------
// Rust dataflow extraction (tree-sitter-rust)
// ---------------------------------------------------------------------------

/// Walk a parsed Rust AST and emit dataflow edges for let/assignment/call/
/// return/field-expression constructs.
pub fn extract_rust_edges(
    tree: &Tree,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
) -> Vec<DataflowEdge> {
    let mut edges = Vec::new();
    let root = tree.root_node();
    walk_rust(
        &mut root.walk(),
        source,
        engagement_id,
        file_path,
        None,
        &mut edges,
    );
    edges
}

fn walk_rust(
    cursor: &mut TreeCursor,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    enclosing_fn: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let node = cursor.node();
    let kind = node.kind();

    // Track function context.
    let new_fn: Option<String> = if kind == "function_item" {
        node.child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok().map(String::from))
    } else {
        None
    };
    let fn_ctx_owned = new_fn;
    let fn_ctx = fn_ctx_owned.as_deref().or(enclosing_fn);

    match kind {
        "let_declaration" => {
            emit_rust_let(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "assignment_expression" | "compound_assignment_expr" => {
            emit_rust_assignment(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "call_expression" => {
            emit_rust_call_arg(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "return_expression" => {
            emit_rust_return(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            walk_rust(cursor, source, engagement_id, file_path, fn_ctx, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// `let <pattern> = <value>;` — emit assign / subscript edges from the value
/// expression to the pattern's primary identifier. If no `value` field is
/// present (declaration without initializer), nothing is emitted.
fn emit_rust_let(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    let to_ident = rust_primary_ident(&pattern, source);
    let line = (pattern.start_position().row + 1) as i64;
    let to = qualify(file_path, fn_ctx, &to_ident);
    emit_rust_rhs_edges(
        &value,
        source,
        engagement_id,
        file_path,
        fn_ctx,
        &to,
        line,
        out,
    );
}

/// `x = y` or `x += y` — emit assign edges from the RHS to the LHS.
fn emit_rust_assignment(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let line = (left.start_position().row + 1) as i64;
    let to_ident = rust_primary_ident(&left, source);
    let to = qualify(file_path, fn_ctx, &to_ident);
    emit_rust_rhs_edges(
        &right,
        source,
        engagement_id,
        file_path,
        fn_ctx,
        &to,
        line,
        out,
    );
}

/// Walk a Rust RHS expression and emit `assign` / `subscript` edges into `to`.
#[allow(clippy::too_many_arguments)]
fn emit_rust_rhs_edges(
    rhs: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    to: &str,
    line: i64,
    out: &mut Vec<DataflowEdge>,
) {
    let mut stack = vec![*rhs];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" => {
                let from = qualify(file_path, fn_ctx, &node_text(&n, source));
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "assign".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "scoped_identifier" => {
                // Treat `a::b::c` as a single symbol.
                let from = qualify(file_path, fn_ctx, &node_text(&n, source));
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "assign".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "field_expression" => {
                // `obj.field` — record an edge from obj as a `subscript` (mirrors
                // Python's subscript convention for member access).
                if let Some(obj) = n.child_by_field_name("value") {
                    let obj_text = node_text(&obj, source);
                    let from = qualify(file_path, fn_ctx, &obj_text);
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "index_expression" => {
                // `arr[i]` — emit subscript edge from the indexed value.
                if let Some(obj) = n.child(0) {
                    let from = qualify(file_path, fn_ctx, &node_text(&obj, source));
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "call_expression" => {
                // Don't descend into the callee — it's handled by walk_rust's
                // own visit which emits `call_arg` edges separately.
            }
            _ => {
                let mut c = n.walk();
                if c.goto_first_child() {
                    loop {
                        stack.push(c.node());
                        if !c.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// `callee(arg1, arg2)` — emit a `call_arg` edge from each argument identifier
/// to the callee's qualified name. Only inspects immediate children of the
/// `arguments` list (depth 1); nested calls are visited by the outer recursion.
fn emit_rust_call_arg(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(callee) = node.child_by_field_name("function") else {
        return;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let callee_q = qualify(file_path, fn_ctx, &node_text(&callee, source));

    let mut c = args.walk();
    if c.goto_first_child() {
        loop {
            let a = c.node();
            if a.kind() == "identifier" || a.kind() == "scoped_identifier" {
                out.push(DataflowEdge {
                    engagement_id,
                    from_symbol: qualify(file_path, fn_ctx, &node_text(&a, source)),
                    to_symbol: callee_q.clone(),
                    edge_kind: "call_arg".into(),
                    file_path: file_path.into(),
                    line,
                });
            }
            if !c.goto_next_sibling() {
                break;
            }
        }
    }
}

/// `return foo;` — emit a `return` edge from each identifier inside the
/// expression to the synthetic `<file>:<fn>:<return>` sink.
fn emit_rust_return(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(fname) = fn_ctx else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let to = format!("{file_path}:{fname}:<return>");
    let mut c = node.walk();
    if !c.goto_first_child() {
        return;
    }
    loop {
        let n = c.node();
        match n.kind() {
            "identifier" | "scoped_identifier" => {
                out.push(DataflowEdge {
                    engagement_id,
                    from_symbol: qualify(file_path, fn_ctx, &node_text(&n, source)),
                    to_symbol: to.clone(),
                    edge_kind: "return".into(),
                    file_path: file_path.into(),
                    line,
                });
            }
            _ => {}
        }
        if !c.goto_next_sibling() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Go dataflow extraction (tree-sitter-go)
//
// Mirrors the Rust extractor's shape (track enclosing function, emit
// assign/subscript/call_arg/return edges) but adapts to two Go-specific
// realities:
//
//  1. Assignments are `short_var_declaration` (`x := y`) and
//     `assignment_statement` (`x = y`), both with `left`/`right`
//     `expression_list` fields. We pair element-wise when arities match
//     (`a, b := f, g`) and otherwise fan every RHS identifier into the first
//     LHS target (`a, err := f(x)`).
//
//  2. Untrusted request data in Go arrives through METHOD CALLS, not field
//     access: `r.FormValue("u")`, `r.URL.Query()`, `ctx.Value("org_id")`,
//     `os.Getenv("X")`. So unlike the Rust RHS walker (which skips call
//     expressions), the Go RHS walker emits an `assign` edge from a call's
//     selector callee (e.g. `r.FormValue`) into the assigned variable. That
//     is what lets a threat-model source like `r.FormValue` actually seed a
//     taint chain.
// ---------------------------------------------------------------------------

/// Walk a parsed Go AST and emit dataflow edges for short-var / assignment /
/// var-spec / call / return constructs.
pub fn extract_go_edges(
    tree: &Tree,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
) -> Vec<DataflowEdge> {
    let mut edges = Vec::new();
    let root = tree.root_node();
    walk_go(
        &mut root.walk(),
        source,
        engagement_id,
        file_path,
        None,
        &mut edges,
    );
    edges
}

fn walk_go(
    cursor: &mut TreeCursor,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    enclosing_fn: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let node = cursor.node();
    let kind = node.kind();

    // Track function/method context.
    let new_fn: Option<String> = if kind == "function_declaration" || kind == "method_declaration" {
        node.child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok().map(String::from))
    } else {
        None
    };
    let fn_ctx_owned = new_fn;
    let fn_ctx = fn_ctx_owned.as_deref().or(enclosing_fn);

    match kind {
        "short_var_declaration" | "assignment_statement" => {
            emit_go_assign(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "var_spec" | "const_spec" => {
            emit_go_var_spec(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "call_expression" => {
            emit_go_call_arg(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "return_statement" => {
            emit_go_return(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            walk_go(cursor, source, engagement_id, file_path, fn_ctx, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// Collect the primary identifier of each element of an `expression_list`
/// (or a single expression node), in order. `r.URL` → `r`, `arr[i]` → `arr`,
/// `x` → `x`.
fn go_lhs_targets(node: &Node, source: &[u8]) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    let mut push = |n: &Node| {
        let ident = go_primary_ident(n, source);
        if !ident.is_empty() {
            out.push((ident, (n.start_position().row + 1) as i64));
        }
    };
    if node.kind() == "expression_list" {
        let mut c = node.walk();
        if c.goto_first_child() {
            loop {
                let n = c.node();
                if n.is_named() {
                    push(&n);
                }
                if !c.goto_next_sibling() {
                    break;
                }
            }
        }
    } else {
        push(node);
    }
    out
}

/// The "primary" identifier feeding/receiving an expression: the base of a
/// selector or index, or the identifier itself.
fn go_primary_ident(node: &Node, source: &[u8]) -> String {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => node_text(node, source),
        "selector_expression" | "index_expression" => node
            .child_by_field_name("operand")
            .map(|o| go_primary_ident(&o, source))
            .unwrap_or_default(),
        _ => {
            // Fall back to the first descendant identifier.
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    let n = c.node();
                    if n.kind() == "identifier" {
                        return node_text(&n, source);
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
            String::new()
        }
    }
}

/// `x := y` / `x = y` / `a, b := f, g`. Pairs left/right element-wise when the
/// arities match; otherwise fans all RHS identifiers into the first LHS target.
fn emit_go_assign(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let targets = go_lhs_targets(&left, source);
    let Some((first_target, _)) = targets.first() else {
        return;
    };

    // Collect RHS elements (named children of the expression_list, or the node).
    let mut rhs_nodes: Vec<Node> = Vec::new();
    if right.kind() == "expression_list" {
        let mut c = right.walk();
        if c.goto_first_child() {
            loop {
                let n = c.node();
                if n.is_named() {
                    rhs_nodes.push(n);
                }
                if !c.goto_next_sibling() {
                    break;
                }
            }
        }
    } else {
        rhs_nodes.push(right);
    }

    if rhs_nodes.len() == targets.len() {
        // Element-wise pairing.
        for (rhs, (tgt, line)) in rhs_nodes.iter().zip(targets.iter()) {
            let to = qualify(file_path, fn_ctx, tgt);
            emit_go_rhs_edges(rhs, source, engagement_id, file_path, fn_ctx, &to, *line, out);
        }
    } else {
        // Arity mismatch (e.g. `v, err := f(x)`): fan every RHS into target 0.
        let line = targets[0].1;
        let to = qualify(file_path, fn_ctx, first_target);
        for rhs in &rhs_nodes {
            emit_go_rhs_edges(rhs, source, engagement_id, file_path, fn_ctx, &to, line, out);
        }
    }
}

/// `var x T = y` / `const x = y` — emit edges from the value(s) to the name(s).
fn emit_go_var_spec(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let to_ident = go_primary_ident(&name, source);
    if to_ident.is_empty() {
        return;
    }
    let line = (name.start_position().row + 1) as i64;
    let to = qualify(file_path, fn_ctx, &to_ident);
    if value.kind() == "expression_list" {
        let mut c = value.walk();
        if c.goto_first_child() {
            loop {
                let n = c.node();
                if n.is_named() {
                    emit_go_rhs_edges(&n, source, engagement_id, file_path, fn_ctx, &to, line, out);
                }
                if !c.goto_next_sibling() {
                    break;
                }
            }
        }
    } else {
        emit_go_rhs_edges(&value, source, engagement_id, file_path, fn_ctx, &to, line, out);
    }
}

/// Walk a Go RHS expression and emit `assign` / `subscript` edges into `to`.
/// Unlike Rust, a `call_expression` with a selector callee emits an `assign`
/// edge from the callee (e.g. `r.FormValue`) so request-method sources seed
/// chains; argument edges are still emitted separately by `walk_go`.
#[allow(clippy::too_many_arguments)]
fn emit_go_rhs_edges(
    rhs: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    to: &str,
    line: i64,
    out: &mut Vec<DataflowEdge>,
) {
    let mut stack = vec![*rhs];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" => {
                let from = qualify(file_path, fn_ctx, &node_text(&n, source));
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "assign".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "selector_expression" => {
                // `a.b` — record the full selector as the source symbol (so
                // `r.URL.Query` / `ctx.Value` match threat-model sources),
                // plus a subscript edge from the base operand.
                let full = node_text(&n, source);
                let from = qualify(file_path, fn_ctx, &full);
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "index_expression" => {
                if let Some(obj) = n.child_by_field_name("operand") {
                    let from = qualify(file_path, fn_ctx, &node_text(&obj, source));
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "call_expression" => {
                // `x := r.FormValue("u")` — link the callee selector into the
                // assigned variable so request-data method calls propagate.
                if let Some(callee) = n.child_by_field_name("function") {
                    if callee.kind() == "selector_expression" {
                        let from = qualify(file_path, fn_ctx, &node_text(&callee, source));
                        if from != to {
                            out.push(DataflowEdge {
                                engagement_id,
                                from_symbol: from,
                                to_symbol: to.to_string(),
                                edge_kind: "assign".into(),
                                file_path: file_path.into(),
                                line,
                            });
                        }
                    }
                }
                // Descend into the arguments so nested identifiers still flow.
                if let Some(args) = n.child_by_field_name("arguments") {
                    let mut c = args.walk();
                    if c.goto_first_child() {
                        loop {
                            stack.push(c.node());
                            if !c.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
            }
            _ => {
                let mut c = n.walk();
                if c.goto_first_child() {
                    loop {
                        stack.push(c.node());
                        if !c.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// `callee(arg1, arg2)` — emit a `call_arg` edge from each argument's primary
/// identifier to the callee's qualified name. The callee text of a selector
/// (`db.Query`, `exec.Command`) is what matches threat-model sinks.
fn emit_go_call_arg(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(callee) = node.child_by_field_name("function") else {
        return;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let callee_q = qualify(file_path, fn_ctx, &node_text(&callee, source));

    let mut c = args.walk();
    if c.goto_first_child() {
        loop {
            let a = c.node();
            if a.is_named() {
                let ident = go_primary_ident(&a, source);
                if !ident.is_empty() {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: qualify(file_path, fn_ctx, &ident),
                        to_symbol: callee_q.clone(),
                        edge_kind: "call_arg".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            if !c.goto_next_sibling() {
                break;
            }
        }
    }
}

/// `return foo` — emit a `return` edge from each identifier inside the
/// expression list to the synthetic `<file>:<fn>:<return>` sink.
fn emit_go_return(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(fname) = fn_ctx else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let to = format!("{file_path}:{fname}:<return>");
    let mut c = node.walk();
    if !c.goto_first_child() {
        return;
    }
    loop {
        let n = c.node();
        if n.is_named() {
            let ident = go_primary_ident(&n, source);
            if !ident.is_empty() {
                out.push(DataflowEdge {
                    engagement_id,
                    from_symbol: qualify(file_path, fn_ctx, &ident),
                    to_symbol: to.clone(),
                    edge_kind: "return".into(),
                    file_path: file_path.into(),
                    line,
                });
            }
        }
        if !c.goto_next_sibling() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Java dataflow extraction (tree-sitter-java)
//
// Mirrors the Go extractor's shape (track enclosing method, emit
// assign/subscript/call_arg/return edges) and adapts to two Java realities:
//
//  1. Local and field initializers are `variable_declarator` nodes with
//     `name`/`value` fields (`String u = ...;` and `private String x = ...;`).
//     Re-assignment is `assignment_expression` with `left`/`right`.
//
//  2. Untrusted request data in Java arrives through METHOD CALLS, not field
//     access: `request.getParameter("u")`, `request.getHeader("X")`,
//     `req.getInputStream()`. Sinks are likewise method calls
//     (`stmt.executeQuery(sql)`, `Runtime.getRuntime().exec(cmd)`). So, like
//     Go, the RHS walker emits an `assign` edge from a `method_invocation`'s
//     reconstructed callee (`object.name`, e.g. `request.getParameter`) into
//     the assigned variable, which lets a threat-model source method seed a
//     taint chain. `call_arg` edges target the same `object.name` callee so
//     sink methods match.
// ---------------------------------------------------------------------------

/// Walk a parsed Java AST and emit dataflow edges for variable declarators,
/// assignments, method invocations, and returns.
pub fn extract_java_edges(
    tree: &Tree,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
) -> Vec<DataflowEdge> {
    let mut edges = Vec::new();
    let root = tree.root_node();
    walk_java(
        &mut root.walk(),
        source,
        engagement_id,
        file_path,
        None,
        &mut edges,
    );
    edges
}

fn walk_java(
    cursor: &mut TreeCursor,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    enclosing_fn: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let node = cursor.node();
    let kind = node.kind();

    // Track method/constructor context so symbol names can include `<fn>:`.
    let new_fn: Option<String> = if kind == "method_declaration" || kind == "constructor_declaration"
    {
        node.child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok().map(String::from))
    } else {
        None
    };
    let fn_ctx_owned = new_fn;
    let fn_ctx = fn_ctx_owned.as_deref().or(enclosing_fn);

    match kind {
        // Covers both `String u = ...;` locals and `private String x = ...;`
        // field declarations — both wrap their initializer in a
        // `variable_declarator`.
        "variable_declarator" => {
            emit_java_var_declarator(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "assignment_expression" => {
            emit_java_assign(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "method_invocation" => {
            emit_java_call_arg(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "return_statement" => {
            emit_java_return(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            walk_java(cursor, source, engagement_id, file_path, fn_ctx, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// The "primary" identifier feeding/receiving a Java expression: the base of a
/// field access / array access / method receiver, or the identifier itself.
fn java_primary_ident(node: &Node, source: &[u8]) -> String {
    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier" => node_text(node, source),
        "field_access" => node
            .child_by_field_name("object")
            .map(|o| java_primary_ident(&o, source))
            .unwrap_or_default(),
        "array_access" => node
            .child_by_field_name("array")
            .map(|a| java_primary_ident(&a, source))
            .unwrap_or_default(),
        "method_invocation" => node
            .child_by_field_name("object")
            .map(|o| java_primary_ident(&o, source))
            .unwrap_or_default(),
        _ => {
            // Fall back to the first descendant identifier.
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    let n = c.node();
                    if n.kind() == "identifier" {
                        return node_text(&n, source);
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
            String::new()
        }
    }
}

/// Reconstruct a method-invocation callee as `object.name` (e.g.
/// `request.getParameter`, `stmt.executeQuery`) so it matches threat-model
/// source/sink method names. Falls back to the bare `name` for unqualified
/// calls (`foo(...)`).
fn java_callee_text(node: &Node, source: &[u8]) -> String {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(&n, source))
        .unwrap_or_default();
    match node.child_by_field_name("object") {
        Some(obj) => {
            let obj_text = node_text(&obj, source);
            if obj_text.is_empty() {
                name
            } else {
                format!("{obj_text}.{name}")
            }
        }
        None => name,
    }
}

/// `Type name = value` (local or field) — emit edges from the initializer into
/// the declared name.
fn emit_java_var_declarator(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };
    let to_ident = node_text(&name, source);
    if to_ident.is_empty() {
        return;
    }
    let line = (name.start_position().row + 1) as i64;
    let to = qualify(file_path, fn_ctx, &to_ident);
    emit_java_rhs_edges(&value, source, engagement_id, file_path, fn_ctx, &to, line, out);
}

/// `lhs = rhs` — emit edges from the RHS into the LHS primary identifier.
fn emit_java_assign(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let to_ident = java_primary_ident(&left, source);
    if to_ident.is_empty() {
        return;
    }
    let line = (left.start_position().row + 1) as i64;
    let to = qualify(file_path, fn_ctx, &to_ident);
    emit_java_rhs_edges(&right, source, engagement_id, file_path, fn_ctx, &to, line, out);
}

/// Walk a Java RHS expression and emit `assign` / `subscript` edges into `to`.
/// A `method_invocation` callee (`request.getParameter`) emits an `assign`
/// edge so request-method sources seed chains; arguments are descended into so
/// nested identifiers (e.g. inside a `"..." + x` concatenation) still flow.
#[allow(clippy::too_many_arguments)]
fn emit_java_rhs_edges(
    rhs: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    to: &str,
    line: i64,
    out: &mut Vec<DataflowEdge>,
) {
    let mut stack = vec![*rhs];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" => {
                let from = qualify(file_path, fn_ctx, &node_text(&n, source));
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "assign".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "field_access" => {
                // `a.b` — record the full access as the source symbol (so
                // `request.queryString`-style field sources match), plus a
                // subscript edge from the base operand.
                let full = node_text(&n, source);
                let from = qualify(file_path, fn_ctx, &full);
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "array_access" => {
                if let Some(arr) = n.child_by_field_name("array") {
                    let from = qualify(file_path, fn_ctx, &node_text(&arr, source));
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "method_invocation" => {
                // `x = request.getParameter("u")` — link the callee into the
                // assigned variable so request-data method calls propagate.
                let callee = java_callee_text(&n, source);
                if !callee.is_empty() {
                    let from = qualify(file_path, fn_ctx, &callee);
                    if from != to {
                        out.push(DataflowEdge {
                            engagement_id,
                            from_symbol: from,
                            to_symbol: to.to_string(),
                            edge_kind: "assign".into(),
                            file_path: file_path.into(),
                            line,
                        });
                    }
                }
                // Descend into arguments so nested identifiers still flow.
                if let Some(args) = n.child_by_field_name("arguments") {
                    let mut c = args.walk();
                    if c.goto_first_child() {
                        loop {
                            stack.push(c.node());
                            if !c.goto_next_sibling() {
                                break;
                            }
                        }
                    }
                }
            }
            _ => {
                let mut c = n.walk();
                if c.goto_first_child() {
                    loop {
                        stack.push(c.node());
                        if !c.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// `callee(arg1, arg2)` — emit a `call_arg` edge from each argument's primary
/// identifier to the reconstructed callee (`object.name`). The callee text of
/// a method invocation (`stmt.executeQuery`, `Runtime.getRuntime().exec`) is
/// what matches threat-model sinks.
fn emit_java_call_arg(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let callee = java_callee_text(node, source);
    if callee.is_empty() {
        return;
    }
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let callee_q = qualify(file_path, fn_ctx, &callee);

    let mut c = args.walk();
    if c.goto_first_child() {
        loop {
            let a = c.node();
            if a.is_named() {
                let ident = java_primary_ident(&a, source);
                if !ident.is_empty() {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: qualify(file_path, fn_ctx, &ident),
                        to_symbol: callee_q.clone(),
                        edge_kind: "call_arg".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            if !c.goto_next_sibling() {
                break;
            }
        }
    }
}

/// `return foo;` — emit a `return` edge from each identifier in the returned
/// expression to the synthetic `<file>:<fn>:<return>` sink.
fn emit_java_return(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(fname) = fn_ctx else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let to = format!("{file_path}:{fname}:<return>");
    let mut c = node.walk();
    if !c.goto_first_child() {
        return;
    }
    loop {
        let n = c.node();
        if n.is_named() {
            let ident = java_primary_ident(&n, source);
            if !ident.is_empty() {
                out.push(DataflowEdge {
                    engagement_id,
                    from_symbol: qualify(file_path, fn_ctx, &ident),
                    to_symbol: to.clone(),
                    edge_kind: "return".into(),
                    file_path: file_path.into(),
                    line,
                });
            }
        }
        if !c.goto_next_sibling() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// PHP dataflow extraction (tree-sitter-php)
//
// Mirrors the Java/Go extractors: assignments, call arguments, and returns
// become `from_symbol -> to_symbol` edges keyed by qualified
// `<file>:<fn>:<ident>` names.
//
// PHP-specific note: request sources are superglobal subscripts
// (`$_GET['id']`). The subscript's base (`$_GET`) is emitted as the
// `from_symbol`, which taint_tracer substring-matches against the
// threat-model source `$_GET`.
// ---------------------------------------------------------------------------

/// Extract PHP dataflow edges. Mirrors the Java/Go extractors: assignments,
/// call arguments, and returns become `from_symbol -> to_symbol` edges keyed
/// by qualified `<file>:<fn>:<ident>` names. The taint-relevant PHP specific
/// is that request sources are superglobal subscripts (`$_GET['id']`): the
/// subscript's base (`$_GET`) is emitted as the `from_symbol`, which
/// taint_tracer substring-matches against the threat-model source `$_GET`.
pub fn extract_php_edges(
    tree: &Tree,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
) -> Vec<DataflowEdge> {
    let mut edges = Vec::new();
    let root = tree.root_node();
    walk_php(&mut root.walk(), source, engagement_id, file_path, None, &mut edges);
    edges
}

fn walk_php(
    cursor: &mut TreeCursor,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    enclosing_fn: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let node = cursor.node();
    let kind = node.kind();

    let new_fn: Option<String> = if kind == "function_definition" || kind == "method_declaration" {
        node.child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok().map(String::from))
    } else {
        None
    };
    let fn_ctx_owned = new_fn;
    let fn_ctx = fn_ctx_owned.as_deref().or(enclosing_fn);

    match kind {
        "assignment_expression" => {
            emit_php_assign(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "function_call_expression" | "member_call_expression" | "scoped_call_expression" => {
            emit_php_call_arg(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "return_statement" => {
            emit_php_return(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            walk_php(cursor, source, engagement_id, file_path, fn_ctx, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// First `variable_name` in pre-order under `node` (its text, incl. the `$`).
/// For a `subscript_expression` like `$_GET['id']`, this is the base `$_GET`.
fn php_primary_ident(node: &Node, source: &[u8]) -> String {
    if node.kind() == "variable_name" {
        return node_text(node, source);
    }
    let mut c = node.walk();
    if c.goto_first_child() {
        loop {
            let found = php_primary_ident(&c.node(), source);
            if !found.is_empty() {
                return found;
            }
            if !c.goto_next_sibling() {
                break;
            }
        }
    }
    String::new()
}

/// Callee name for a PHP call. Plain calls use the function text
/// (`mysqli_query`); method calls use `->name`; static calls use `scope::name`.
fn php_callee_text(node: &Node, source: &[u8]) -> String {
    match node.kind() {
        "function_call_expression" => node
            .child_by_field_name("function")
            .map(|n| node_text(&n, source))
            .unwrap_or_default(),
        "member_call_expression" => node
            .child_by_field_name("name")
            .map(|n| format!("->{}", node_text(&n, source)))
            .unwrap_or_default(),
        "scoped_call_expression" => {
            let scope = node
                .child_by_field_name("scope")
                .map(|n| node_text(&n, source))
                .unwrap_or_default();
            let name = node
                .child_by_field_name("name")
                .map(|n| node_text(&n, source))
                .unwrap_or_default();
            if name.is_empty() {
                String::new()
            } else {
                format!("{scope}::{name}")
            }
        }
        _ => String::new(),
    }
}

fn emit_php_assign(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let to_ident = php_primary_ident(&left, source);
    if to_ident.is_empty() {
        return;
    }
    let line = (left.start_position().row + 1) as i64;
    let to = qualify(file_path, fn_ctx, &to_ident);

    // Walk the RHS: `variable_name` -> assign edge; `subscript_expression` ->
    // edge from its base (do not descend, so `$_GET['id']` is one edge).
    let mut stack = vec![right];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "variable_name" => {
                let from = qualify(file_path, fn_ctx, &node_text(&n, source));
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.clone(),
                        edge_kind: "assign".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "subscript_expression" => {
                let base = php_primary_ident(&n, source);
                if !base.is_empty() {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: qualify(file_path, fn_ctx, &base),
                        to_symbol: to.clone(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            _ => {
                let mut c = n.walk();
                if c.goto_first_child() {
                    loop {
                        stack.push(c.node());
                        if !c.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn emit_php_call_arg(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let callee = php_callee_text(node, source);
    if callee.is_empty() {
        return;
    }
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let callee_q = qualify(file_path, fn_ctx, &callee);

    let mut c = args.walk();
    if c.goto_first_child() {
        loop {
            let a = c.node();
            if a.is_named() {
                let ident = php_primary_ident(&a, source);
                if !ident.is_empty() {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: qualify(file_path, fn_ctx, &ident),
                        to_symbol: callee_q.clone(),
                        edge_kind: "call_arg".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            if !c.goto_next_sibling() {
                break;
            }
        }
    }
}

fn emit_php_return(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(fname) = fn_ctx else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let mut stack = vec![*node];
    while let Some(n) = stack.pop() {
        if n.kind() == "variable_name" {
            out.push(DataflowEdge {
                engagement_id,
                from_symbol: qualify(file_path, fn_ctx, &node_text(&n, source)),
                to_symbol: format!("{file_path}:{fname}:<return>"),
                edge_kind: "return".into(),
                file_path: file_path.into(),
                line,
            });
        } else {
            let mut c = n.walk();
            if c.goto_first_child() {
                loop {
                    stack.push(c.node());
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TypeScript / JavaScript dataflow extraction (tree-sitter-typescript /
// tree-sitter-javascript share most node kinds for the constructs we care
// about: variable_declarator, assignment_expression, call_expression,
// member_expression, subscript_expression, return_statement).
// ---------------------------------------------------------------------------

/// Walk a parsed TypeScript (or JavaScript / TSX) AST and emit dataflow
/// edges for lexical/var/assignment/call/return/member/subscript constructs.
pub fn extract_typescript_edges(
    tree: &Tree,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
) -> Vec<DataflowEdge> {
    let mut edges = Vec::new();
    let root = tree.root_node();
    walk_ts(
        &mut root.walk(),
        source,
        engagement_id,
        file_path,
        None,
        &mut edges,
    );
    edges
}

fn walk_ts(
    cursor: &mut TreeCursor,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    enclosing_fn: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let node = cursor.node();
    let kind = node.kind();

    // Track function context. function_declaration / function_expression /
    // arrow_function / method_definition / generator_function_declaration all
    // expose a `name` field when one is present; arrow_function often is
    // anonymous so we leave fn_ctx unchanged in that case.
    let new_fn: Option<String> = match kind {
        "function_declaration"
        | "function_expression"
        | "method_definition"
        | "generator_function_declaration" => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok().map(String::from)),
        _ => None,
    };
    let fn_ctx_owned = new_fn;
    let fn_ctx = fn_ctx_owned.as_deref().or(enclosing_fn);

    match kind {
        "variable_declarator" => {
            emit_ts_declarator(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "assignment_expression" | "augmented_assignment_expression" => {
            emit_ts_assignment(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "call_expression" => {
            emit_ts_call_arg(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        "return_statement" => {
            emit_ts_return(&node, source, engagement_id, file_path, fn_ctx, out);
        }
        _ => {}
    }

    if cursor.goto_first_child() {
        loop {
            walk_ts(cursor, source, engagement_id, file_path, fn_ctx, out);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

/// `const x = expr;` / `let x = expr;` / `var x = expr;` — emit assign /
/// subscript edges from the value to the declarator's name.
fn emit_ts_declarator(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        // Declaration without initializer (`let x;`).
        return;
    };
    let line = (name.start_position().row + 1) as i64;
    let to_ident = ts_primary_ident(&name, source);
    let to = qualify(file_path, fn_ctx, &to_ident);
    emit_ts_rhs_edges(
        &value,
        source,
        engagement_id,
        file_path,
        fn_ctx,
        &to,
        line,
        out,
    );
}

/// `x = y` / `x += y` — emit assign edges from the RHS to the LHS.
fn emit_ts_assignment(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(right) = node.child_by_field_name("right") else {
        return;
    };
    let line = (left.start_position().row + 1) as i64;
    let to_ident = ts_primary_ident(&left, source);
    let to = qualify(file_path, fn_ctx, &to_ident);
    emit_ts_rhs_edges(
        &right,
        source,
        engagement_id,
        file_path,
        fn_ctx,
        &to,
        line,
        out,
    );
}

/// Walk a TS RHS expression and emit `assign` / `subscript` edges into `to`.
#[allow(clippy::too_many_arguments)]
fn emit_ts_rhs_edges(
    rhs: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    to: &str,
    line: i64,
    out: &mut Vec<DataflowEdge>,
) {
    let mut stack = vec![*rhs];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" | "shorthand_property_identifier" => {
                let from = qualify(file_path, fn_ctx, &node_text(&n, source));
                if from != to {
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "assign".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "member_expression" => {
                // `obj.prop` — record an edge from obj as a `subscript` edge.
                if let Some(obj) = n.child_by_field_name("object") {
                    let from = qualify(file_path, fn_ctx, &node_text(&obj, source));
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "subscript_expression" => {
                // `obj[k]` — emit a subscript edge from the object.
                if let Some(obj) = n.child_by_field_name("object") {
                    let from = qualify(file_path, fn_ctx, &node_text(&obj, source));
                    out.push(DataflowEdge {
                        engagement_id,
                        from_symbol: from,
                        to_symbol: to.to_string(),
                        edge_kind: "subscript".into(),
                        file_path: file_path.into(),
                        line,
                    });
                }
            }
            "call_expression" => {
                // Don't descend — walk_ts visits this separately and emits
                // `call_arg` edges for its arguments.
            }
            _ => {
                let mut c = n.walk();
                if c.goto_first_child() {
                    loop {
                        stack.push(c.node());
                        if !c.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// `callee(arg1, arg2)` — emit a `call_arg` edge from each argument identifier
/// to the callee's qualified name. Only inspects immediate children of the
/// `arguments` list; nested calls are visited by the outer recursion.
fn emit_ts_call_arg(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(callee) = node.child_by_field_name("function") else {
        return;
    };
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let callee_q = qualify(file_path, fn_ctx, &node_text(&callee, source));

    let mut c = args.walk();
    if c.goto_first_child() {
        loop {
            let a = c.node();
            if a.kind() == "identifier" {
                out.push(DataflowEdge {
                    engagement_id,
                    from_symbol: qualify(file_path, fn_ctx, &node_text(&a, source)),
                    to_symbol: callee_q.clone(),
                    edge_kind: "call_arg".into(),
                    file_path: file_path.into(),
                    line,
                });
            }
            if !c.goto_next_sibling() {
                break;
            }
        }
    }
}

/// `return x;` — emit a `return` edge from each identifier inside the
/// expression to the synthetic `<file>:<fn>:<return>` sink.
fn emit_ts_return(
    node: &Node,
    source: &[u8],
    engagement_id: Uuid,
    file_path: &str,
    fn_ctx: Option<&str>,
    out: &mut Vec<DataflowEdge>,
) {
    let Some(fname) = fn_ctx else {
        return;
    };
    let line = (node.start_position().row + 1) as i64;
    let to = format!("{file_path}:{fname}:<return>");
    let mut c = node.walk();
    if !c.goto_first_child() {
        return;
    }
    loop {
        let n = c.node();
        if n.kind() == "identifier" {
            out.push(DataflowEdge {
                engagement_id,
                from_symbol: qualify(file_path, fn_ctx, &node_text(&n, source)),
                to_symbol: to.clone(),
                edge_kind: "return".into(),
                file_path: file_path.into(),
                line,
            });
        }
        if !c.goto_next_sibling() {
            break;
        }
    }
}

/// Extract the primary identifier from a TS/JS l-value / declarator name.
/// Handles `identifier`, `array_pattern` / `object_pattern` (first element).
fn ts_primary_ident(node: &Node, source: &[u8]) -> String {
    match node.kind() {
        "identifier" | "property_identifier" => node_text(node, source),
        "array_pattern" | "object_pattern" => {
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    let ch = c.node();
                    match ch.kind() {
                        "identifier" | "shorthand_property_identifier_pattern" => {
                            return node_text(&ch, source);
                        }
                        _ => {}
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
            node_text(node, source)
        }
        _ => node_text(node, source),
    }
}

/// Extract the primary identifier from a Rust pattern or l-value expression.
/// Handles common cases: bare `identifier`, `mut_pattern`, `ref_pattern`,
/// `tuple_pattern` (first element), `field_expression` (full text). Falls back
/// to the node's full text.
fn rust_primary_ident(node: &Node, source: &[u8]) -> String {
    match node.kind() {
        "identifier" => node_text(node, source),
        // `mut x` / `ref x` / `&x` — descend to the inner identifier.
        "mut_pattern" | "ref_pattern" | "reference_pattern" => node
            .child_by_field_name("pattern")
            .map(|p| rust_primary_ident(&p, source))
            .unwrap_or_else(|| node_text(node, source)),
        // `(a, b)` — use the first child identifier we find.
        "tuple_pattern" => {
            let mut c = node.walk();
            if c.goto_first_child() {
                loop {
                    let ch = c.node();
                    if ch.kind() == "identifier" {
                        return node_text(&ch, source);
                    }
                    if !c.goto_next_sibling() {
                        break;
                    }
                }
            }
            node_text(node, source)
        }
        _ => node_text(node, source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_sitter_loader::{parse, SupportedLanguage};

    fn edges_for(src: &str) -> Vec<DataflowEdge> {
        let tree = parse(SupportedLanguage::Python, src.as_bytes()).expect("parse");
        extract_python_edges(&tree, src.as_bytes(), Uuid::new_v4(), "test.py")
    }

    #[test]
    fn assign_from_identifier_emits_edge() {
        let edges = edges_for("def f():\n    x = y\n");
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.py:f:y"
                    && e.to_symbol == "test.py:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign edge y->x; got {edges:?}"
        );
    }

    #[test]
    fn subscript_emits_subscript_edge() {
        let edges =
            edges_for("def list_users():\n    name = request.args['name']\n");
        // The qualifier for `request.args` may be the attribute or its
        // leftmost ident; we accept either as long as edge_kind is subscript.
        assert!(
            edges
                .iter()
                .any(|e| { e.to_symbol == "test.py:list_users:name" && e.edge_kind == "subscript" }),
            "expected subscript edge into name; got {edges:?}"
        );
    }

    #[test]
    fn call_with_arg_emits_call_arg_edge() {
        let edges = edges_for("def f(x):\n    cursor.execute(query)\n");
        assert!(
            edges
                .iter()
                .any(|e| { e.from_symbol == "test.py:f:query" && e.edge_kind == "call_arg" }),
            "expected call_arg edge from query; got {edges:?}"
        );
    }

    #[test]
    fn return_emits_return_edge_to_synthetic_return_symbol() {
        let edges = edges_for("def f():\n    x = 1\n    return x\n");
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.py:f:x"
                    && e.to_symbol == "test.py:f:<return>"
                    && e.edge_kind == "return"
            }),
            "expected return edge from x; got {edges:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Rust extractor tests
    // -----------------------------------------------------------------------

    fn rust_edges_for(src: &str) -> Vec<DataflowEdge> {
        let tree = parse(SupportedLanguage::Rust, src.as_bytes()).expect("parse rust");
        extract_rust_edges(&tree, src.as_bytes(), Uuid::new_v4(), "test.rs")
    }

    #[test]
    fn rust_let_assign_emits_edge() {
        let src = "fn f() { let x = y; }";
        let edges = rust_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.rs:f:y"
                    && e.to_symbol == "test.rs:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign y->x; got {edges:?}"
        );
    }

    #[test]
    fn rust_assignment_expression_emits_edge() {
        let src = "fn f() { let mut x = 0; x = y; }";
        let edges = rust_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.rs:f:y"
                    && e.to_symbol == "test.rs:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign y->x from assignment_expression; got {edges:?}"
        );
    }

    #[test]
    fn rust_field_access_emits_subscript_edge() {
        let src = "fn handler() { let name = req.query; }";
        let edges = rust_edges_for(src);
        // Either a subscript edge from req to name, or an assign edge (if the
        // field_expression branch wasn't taken) — accept either; the spec says
        // "tolerate either".
        assert!(
            edges.iter().any(|e| {
                e.to_symbol == "test.rs:handler:name"
                    && (e.edge_kind == "subscript" || e.edge_kind == "assign")
                    && e.from_symbol.contains("req")
            }),
            "expected edge from req into name; got {edges:?}"
        );
        // Preferably it's a subscript edge.
        assert!(
            edges
                .iter()
                .any(|e| e.edge_kind == "subscript" && e.to_symbol == "test.rs:handler:name"),
            "expected subscript edge into name; got {edges:?}"
        );
    }

    #[test]
    fn rust_call_with_arg_emits_call_arg_edge() {
        let src = "fn f(q: String) { sqlx::query(q); }";
        let edges = rust_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.rs:f:q"
                    && e.edge_kind == "call_arg"
                    && e.to_symbol.contains("query")
            }),
            "expected call_arg edge from q into sqlx::query; got {edges:?}"
        );
    }

    #[test]
    fn rust_return_emits_return_edge() {
        let src = "fn f() -> i32 { let x = 1; return x; }";
        let edges = rust_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.rs:f:x"
                    && e.to_symbol == "test.rs:f:<return>"
                    && e.edge_kind == "return"
            }),
            "expected return edge from x; got {edges:?}"
        );
    }

    // -----------------------------------------------------------------------
    // TypeScript extractor tests
    // -----------------------------------------------------------------------

    fn ts_edges_for(src: &str) -> Vec<DataflowEdge> {
        let tree = parse(SupportedLanguage::TypeScript, src.as_bytes()).expect("parse ts");
        extract_typescript_edges(&tree, src.as_bytes(), Uuid::new_v4(), "test.ts")
    }

    #[test]
    fn ts_const_assign_emits_edge() {
        let src = "function f() { const x = y; }";
        let edges = ts_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.ts:f:y"
                    && e.to_symbol == "test.ts:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign y->x; got {edges:?}"
        );
    }

    #[test]
    fn ts_let_reassignment_emits_edge() {
        let src = "function f() { let x = 0; x = y; }";
        let edges = ts_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.ts:f:y"
                    && e.to_symbol == "test.ts:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign y->x from assignment_expression; got {edges:?}"
        );
    }

    #[test]
    fn ts_member_access_emits_subscript_edge() {
        let src = "function handler() { const name = req.query; }";
        let edges = ts_edges_for(src);
        assert!(
            edges
                .iter()
                .any(|e| e.edge_kind == "subscript" && e.to_symbol == "test.ts:handler:name"),
            "expected subscript edge into name; got {edges:?}"
        );
    }

    #[test]
    fn ts_subscript_expression_emits_subscript_edge() {
        let src = "function handler() { const name = req[key]; }";
        let edges = ts_edges_for(src);
        assert!(
            edges
                .iter()
                .any(|e| e.edge_kind == "subscript" && e.to_symbol == "test.ts:handler:name"),
            "expected subscript edge into name; got {edges:?}"
        );
    }

    #[test]
    fn ts_call_with_arg_emits_call_arg_edge() {
        let src = "function f(q) { db.query(q); }";
        let edges = ts_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.ts:f:q"
                    && e.edge_kind == "call_arg"
                    && e.to_symbol.contains("query")
            }),
            "expected call_arg edge from q into db.query; got {edges:?}"
        );
    }

    #[test]
    fn ts_return_emits_return_edge() {
        let src = "function f() { const x = 1; return x; }";
        let edges = ts_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.ts:f:x"
                    && e.to_symbol == "test.ts:f:<return>"
                    && e.edge_kind == "return"
            }),
            "expected return edge from x; got {edges:?}"
        );
    }

    // --- Go ----------------------------------------------------------------

    fn go_edges_for(src: &str) -> Vec<DataflowEdge> {
        let tree = parse(SupportedLanguage::Go, src.as_bytes()).expect("parse go");
        extract_go_edges(&tree, src.as_bytes(), Uuid::new_v4(), "test.go")
    }

    #[test]
    fn go_short_var_emits_assign_edge() {
        let src = "func f() { x := y }";
        let edges = go_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.go:f:y"
                    && e.to_symbol == "test.go:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign y->x from short_var_declaration; got {edges:?}"
        );
    }

    /// The Go-specific case that makes request-handler taint chains possible:
    /// untrusted data arrives via a method call (`r.FormValue("u")`) and must
    /// propagate into the assigned variable, then into a sink call.
    #[test]
    fn go_request_method_source_flows_to_sink() {
        let src = r#"
            func handler(w http.ResponseWriter, r *http.Request) {
                name := r.FormValue("user")
                db.Query(name)
            }
        "#;
        let edges = go_edges_for(src);
        // source method call -> variable
        assert!(
            edges.iter().any(|e| {
                e.from_symbol.contains("r.FormValue")
                    && e.to_symbol == "test.go:handler:name"
                    && e.edge_kind == "assign"
            }),
            "expected r.FormValue -> name; got {edges:?}"
        );
        // variable -> sink call
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.go:handler:name"
                    && e.to_symbol.contains("db.Query")
                    && e.edge_kind == "call_arg"
            }),
            "expected name -> db.Query call_arg; got {edges:?}"
        );
    }

    #[test]
    fn go_assignment_statement_emits_edge() {
        let src = "func f() { var x int; x = y }";
        let edges = go_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.go:f:y"
                    && e.to_symbol == "test.go:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign y->x from assignment_statement; got {edges:?}"
        );
    }

    #[test]
    fn go_return_emits_return_edge() {
        let src = "func f() int { x := 1; return x }";
        let edges = go_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.go:f:x"
                    && e.to_symbol == "test.go:f:<return>"
                    && e.edge_kind == "return"
            }),
            "expected return edge from x; got {edges:?}"
        );
    }

    // --- Java --------------------------------------------------------------

    fn java_edges_for(src: &str) -> Vec<DataflowEdge> {
        let tree = parse(SupportedLanguage::Java, src.as_bytes()).expect("parse java");
        extract_java_edges(&tree, src.as_bytes(), Uuid::new_v4(), "test.java")
    }

    #[test]
    fn java_local_var_emits_assign_edge() {
        let src = "class C { void f() { String x = y; } }";
        let edges = java_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.java:f:y"
                    && e.to_symbol == "test.java:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign y->x from variable_declarator; got {edges:?}"
        );
    }

    #[test]
    fn java_reassignment_emits_assign_edge() {
        let src = "class C { void f() { String x; x = y; } }";
        let edges = java_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.java:f:y"
                    && e.to_symbol == "test.java:f:x"
                    && e.edge_kind == "assign"
            }),
            "expected assign y->x from assignment_expression; got {edges:?}"
        );
    }

    #[test]
    fn java_request_method_seeds_chain() {
        // `request.getParameter(...)` is the canonical Java taint source; the
        // RHS walker must emit an assign edge from the reconstructed callee.
        let src = "class C { void f() { String u = request.getParameter(\"id\"); } }";
        let edges = java_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol.contains("getParameter")
                    && e.to_symbol == "test.java:f:u"
                    && e.edge_kind == "assign"
            }),
            "expected assign request.getParameter->u; got {edges:?}"
        );
    }

    #[test]
    fn java_field_access_emits_subscript_edge() {
        let src = "class C { void f() { String n = req.queryString; } }";
        let edges = java_edges_for(src);
        assert!(
            edges
                .iter()
                .any(|e| e.edge_kind == "subscript" && e.to_symbol == "test.java:f:n"),
            "expected subscript edge into n; got {edges:?}"
        );
    }

    #[test]
    fn java_call_arg_emits_edge() {
        let src = "class C { void f(String q) { stmt.executeQuery(q); } }";
        let edges = java_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.java:f:q"
                    && e.edge_kind == "call_arg"
                    && e.to_symbol.contains("executeQuery")
            }),
            "expected call_arg edge from q into stmt.executeQuery; got {edges:?}"
        );
    }

    #[test]
    fn java_return_emits_return_edge() {
        let src = "class C { int f() { int x = 1; return x; } }";
        let edges = java_edges_for(src);
        assert!(
            edges.iter().any(|e| {
                e.from_symbol == "test.java:f:x"
                    && e.to_symbol == "test.java:f:<return>"
                    && e.edge_kind == "return"
            }),
            "expected return edge from x; got {edges:?}"
        );
    }

    /// End-to-end source→sink: a request parameter concatenated into a SQL
    /// string passed to `executeQuery`. The three edges below are exactly what
    /// `taint_tracer` BFS-walks to surface the SQLi chain.
    #[test]
    fn java_sqli_source_to_sink_chain() {
        let src = r#"
class Handler {
    void doGet(HttpServletRequest req, Statement stmt) {
        String id = req.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + id;
        stmt.executeQuery(query);
    }
}
"#;
        let edges = java_edges_for(src);
        let has = |from_sub: &str, to_sub: &str, kind: &str| {
            edges.iter().any(|e| {
                e.from_symbol.contains(from_sub)
                    && e.to_symbol.contains(to_sub)
                    && e.edge_kind == kind
            })
        };
        assert!(
            has("getParameter", "doGet:id", "assign"),
            "missing source edge getParameter->id; got {edges:?}"
        );
        assert!(
            has("doGet:id", "doGet:query", "assign"),
            "missing propagation edge id->query; got {edges:?}"
        );
        assert!(
            has("doGet:query", "executeQuery", "call_arg"),
            "missing sink edge query->executeQuery; got {edges:?}"
        );
    }

    // --- PHP ---------------------------------------------------------------

    #[test]
    fn php_get_to_mysqli_query_chain() {
        let src = br#"<?php
function handler($conn) {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = " . $id;
    mysqli_query($conn, $sql);
}
"#;
        let tree = parse(SupportedLanguage::Php, src).unwrap();
        let edges = extract_php_edges(&tree, src, Uuid::nil(), "app.php");
        let has = |from_sub: &str, to_sub: &str, kind: &str| {
            edges.iter().any(|e| {
                e.from_symbol.contains(from_sub)
                    && e.to_symbol.contains(to_sub)
                    && e.edge_kind == kind
            })
        };
        // $_GET['id'] -> $id   (subscript)
        assert!(has("$_GET", "$id", "subscript"), "missing $_GET->$id; edges={edges:?}");
        // $id -> $sql          (assign, via "." concat RHS)
        assert!(has("$id", "$sql", "assign"), "missing $id->$sql; edges={edges:?}");
        // $sql -> mysqli_query (call_arg)
        assert!(has("$sql", "mysqli_query", "call_arg"), "missing $sql->mysqli_query; edges={edges:?}");
    }

    #[test]
    fn php_return_edge() {
        let src = br#"<?php
function f() {
    $x = $_POST['a'];
    return $x;
}
"#;
        let tree = parse(SupportedLanguage::Php, src).unwrap();
        let edges = extract_php_edges(&tree, src, Uuid::nil(), "r.php");
        assert!(edges.iter().any(|e| {
            e.from_symbol.contains("$x") && e.to_symbol.contains("<return>") && e.edge_kind == "return"
        }), "missing return edge; edges={edges:?}");
    }
}
