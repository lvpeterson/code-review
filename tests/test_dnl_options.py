"""Option reader: assignments in option lambdas and initializers, constants, TimeSpans (hand-built IR)."""
from checks.dnl.options import (UNKNOWN, Opt, always_true, assignments, const, lambda_args, opt, options_of,
                                timespan_minutes)


def name(i):
    return {"k": "name", "id": i, "line": 1}


def member(obj, n):
    return {"k": "member", "obj": obj, "name": n, "line": 1}


def lit(v, t=None):
    t = t or ("bool" if isinstance(v, bool) else "null" if v is None else "string" if isinstance(v, str) else "number")
    return {"k": "lit", "v": v, "t": t, "line": 1}


def assign(root, path, value, line=1):
    tgt = name(root)
    for p in path.split("."):
        tgt = member(tgt, p)
    return {"k": "assign", "target": tgt, "op": "=", "value": value, "line": line}


def lam(params, body):
    return {"k": "lambda", "params": params, "body": body, "line": 1}


def call(obj, n, args=None, named=None):
    fn = member(obj, n) if obj is not None else name(n)
    return {"k": "call", "fn": fn, "args": args or [], "named": named or {}, "line": 1}


def test_assignments_in_lambda_body_any_depth():
    body = [assign("o", "Password.RequiredLength", lit(4), 3),
            {"k": "if", "cond": name("x"), "then": [assign("o", "Cookie.HttpOnly", lit(False), 5)], "else": []}]
    got = assignments(lam(["o"], body))
    assert [(a.path, a.line) for a in got] == [("Password.RequiredLength", 3), ("Cookie.HttpOnly", 5)]
    assert all(isinstance(a, Opt) for a in got)


def test_assignments_ignores_non_parameter_roots_and_compound_ops():
    other = assign("local", "X", lit(1))
    plus = dict(assign("o", "Y", lit(1)), op="+=")
    assert assignments(lam(["o"], [other, plus])) == []


def test_assignments_nested_lambda_and_object_value():
    inner = lam(["c"], [assign("c", "Flag", lit(True))])
    outer = lam(["o"], [assign("o", "Events.OnX", inner)])
    paths = [a.path for a in assignments(outer)]
    assert paths == ["Events.OnX", "Flag"]


def test_initializer_entries_with_prefixes():
    node = {"k": "new", "type": "TokenValidationParameters", "args": [], "line": 1, "init": [
        {"name": "ValidateIssuer", "value": lit(False)},
        # The helper lowers a nested object initializer as unknown text.
        {"name": "Nested", "value": {"k": "unknown", "text": "{ A = 1, Deep = { B = true } }", "line": 1}},
        {"name": "X", "value": {"k": "new", "type": "Foo", "args": [], "line": 1,
                                "init": [{"name": "Q", "value": lit(2)}]}},
        {"name": "Y", "value": {"k": "new", "type": None, "args": [], "line": 1,
                                "init": [{"name": "R", "value": lit(3)}]}}]}
    got = {a.path: a for a in assignments(node)}
    assert set(got) == {"ValidateIssuer", "Nested.A", "Nested.Deep.B", "X", "X.Q", "Y.R"}
    assert const(got["Nested.A"].value) == 1
    assert const(got["Nested.Deep.B"].value) is True


def test_initializer_under_assignment_prefix():
    new = {"k": "new", "type": "T", "args": [], "line": 1, "init": [{"name": "ValidateAudience", "value": lit(False)}]}
    paths = [a.path for a in assignments(lam(["o"], [assign("o", "TokenValidationParameters", new)]))]
    assert paths == ["TokenValidationParameters", "TokenValidationParameters.ValidateAudience"]


def test_lambda_args_and_options_of():
    l1, l2 = lam(["a"], [assign("a", "A", lit(1))]), lam(["b"], [assign("b", "B", lit(2))])
    new = {"k": "new", "type": "T", "args": [], "line": 1, "init": [{"name": "C", "value": lit(3)}]}
    c = call(name("services"), "AddThing", [l1, name("x"), new], {"configure": l2})
    assert lambda_args(c) == [l1, l2]
    assert [o.path for o in options_of(c)] == ["A", "C", "B"]


def test_const():
    assert const(lit(None)) is None
    assert const(lit(True)) is True
    assert const(lit(5)) == 5
    assert const(lit("x")) == "x"
    assert const(lit(-1)) == -1
    assert const(member(name("CookieSecurePolicy"), "None")) == "CookieSecurePolicy.None"
    q = member(member(name("Microsoft"), "CookieSecurePolicy"), "Always")
    assert const(q) == "CookieSecurePolicy.Always"
    assert const(member(member(member(name("Microsoft"), "AspNetCore"), "CookieSecurePolicy"), "None")) \
        == "CookieSecurePolicy.None"
    assert const(member(name("SameSiteMode"), "None")) == "SameSiteMode.None"
    # A variable, field or `this` member is a runtime value, never an enum member.
    assert const(member(name("settings"), "Policy")) is UNKNOWN
    assert const(member(name("_policy"), "Value")) is UNKNOWN
    assert const(member({"k": "this", "line": 1}, "X")) is UNKNOWN
    assert const(member(name("this"), "X")) is UNKNOWN
    assert const(call(name("cfg"), "GetValue")) is UNKNOWN
    assert const(name("flag")) is UNKNOWN
    assert const(None) is UNKNOWN
    assert const({"k": "unary", "op": "!", "e": name("isDev")}) is UNKNOWN


def test_always_true():
    assert always_true(lam(["_"], lit(True)))
    assert always_true(lam(["a", "b"], lit(True)))
    assert always_true(lam(["x"], [{"k": "return", "value": lit(True), "line": 1}]))
    assert not always_true(lam(["x"], member(name("x"), "Ok")))
    assert not always_true(lam(["x"], [{"k": "return", "value": lit(False), "line": 1}]))
    assert not always_true(lam(["x"], [{"k": "if", "cond": name("c"), "then": [
        {"k": "return", "value": lit(False), "line": 1}], "else": []},
        {"k": "return", "value": lit(True), "line": 1}]))
    assert not always_true(lam(["x"], []))
    assert not always_true(None)
    assert not always_true(lit(True))


def test_timespan_minutes():
    ts = name("TimeSpan")
    assert timespan_minutes(call(ts, "FromHours", [lit(2)])) == 120
    assert timespan_minutes(call(ts, "FromDays", [lit(30)])) == 43200
    assert timespan_minutes(call(ts, "FromMinutes", [lit(5)])) == 5
    assert timespan_minutes(call(ts, "FromSeconds", [lit(90)])) == 1.5
    new = {"k": "new", "type": "TimeSpan", "args": [lit(1), lit(30), lit(0)], "init": [], "line": 1}
    assert timespan_minutes(new) == 90
    assert timespan_minutes(call(ts, "FromHours", [name("h")])) is None
    assert timespan_minutes(call(name("Other"), "FromHours", [lit(2)])) is None
    assert timespan_minutes(None) is None


def test_opt_last_match_case_insensitive():
    a, b, c = Opt("Password.RequiredLength", lit(4), 1), Opt("x", lit(1), 2), Opt("password.requiredlength", lit(8), 3)
    assert opt([a, b, c], "Password.RequiredLength") is c
    assert opt([a, b], "missing") is None
