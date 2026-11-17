"""Option reader: assignments in option lambdas and initializers, constants, TimeSpans (hand-built IR)."""
from checks.dnl.options import (UNKNOWN, Opt, always_true, assignments, const, lambda_args, opt, options_of, verdict,
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


# -- conditional assignments and verdict ----------------------------------------------------------------

def _cond_flags(body):
    return [(a.path, a.conditional) for a in assignments(lam(["o"], body))]


def test_straight_line_assignment_is_not_conditional():
    assert _cond_flags([assign("o", "A", lit(1))]) == [("A", False)]


def test_assignment_under_if_else_is_conditional():
    body = [{"k": "if", "cond": name("x"), "then": [assign("o", "A", lit(1))], "else": [assign("o", "B", lit(2))]}]
    assert _cond_flags(body) == [("A", True), ("B", True)]


def test_assignment_under_loop_is_conditional():
    body = [{"k": "loop", "body": [assign("o", "A", lit(1))], "line": 1}]
    assert _cond_flags(body) == [("A", True)]


def test_assignment_in_ternary_branch_is_conditional():
    value = {"k": "cond", "c": name("x"), "t": {"k": "assign", "target": member(name("o"), "A"), "op": "=",
                                                "value": lit(1), "line": 1}, "f": lit(0), "line": 1}
    assert _cond_flags([{"k": "expr", "e": value, "line": 1}]) == [("A", True)]


def test_try_body_unconditional_catch_conditional():
    body = [{"k": "try", "body": [assign("o", "A", lit(1))], "catches": [{"body": [assign("o", "B", lit(2))]}],
             "finally": [assign("o", "C", lit(3))], "line": 1}]
    assert _cond_flags(body) == [("A", False), ("B", True), ("C", False)]


def test_initializer_entries_are_not_conditional():
    new = {"k": "new", "type": "T", "args": [], "init": [{"name": "A", "value": lit(1)}], "line": 1}
    assert [(a.path, a.conditional) for a in assignments(new)] == [("A", False)]


def test_verdict_plain_and_absent():
    opts = assignments(lam(["o"], [assign("o", "A", lit(1)), assign("o", "A", lit(2))]))
    o, uncertain = verdict(opts, "a")
    assert o.value["v"] == 2 and uncertain is False
    assert verdict(opts, "Missing") == (None, False)


def test_verdict_conditional_is_uncertain():
    body = [assign("o", "A", lit(True)),
            {"k": "if", "cond": name("x"), "then": [assign("o", "A", lit(False))], "else": []}]
    opts = assignments(lam(["o"], body))
    o, uncertain = verdict(opts, "A")
    assert uncertain is True and o.value["v"] is False      # last wins when no `bad` predicate is given


def test_verdict_bad_predicate_keeps_the_bad_value():
    body = [assign("o", "A", lit(True)),
            {"k": "if", "cond": name("x"), "then": [assign("o", "A", lit(False))], "else": []}]
    opts = assignments(lam(["o"], body))
    o, uncertain = verdict(opts, "A", bad=lambda x: const(x.value) is not False)
    assert uncertain is True and o.value["v"] is True       # the conditional good value never clears it


# -- early exits make the following statements conditional ---------------------------------------------

def _ret():
    return {"k": "return", "value": None, "line": 1}


def _if(then):
    return {"k": "if", "cond": name("x"), "then": then, "else": []}


def test_guarded_return_makes_following_assignments_conditional():
    body = [assign("o", "A", lit(1)), _if([_ret()]), assign("o", "B", lit(2))]
    assert _cond_flags(body) == [("A", False), ("B", True)]


def test_guarded_throw_and_break_make_following_conditional():
    for jump in ({"k": "throw", "value": None, "line": 1}, {"k": "other", "text": "break;", "line": 1},
                 {"k": "other", "text": "continue;", "line": 1}, {"k": "other", "text": "goto end;", "line": 1}):
        assert _cond_flags([_if([jump]), assign("o", "B", lit(2))]) == [("B", True)], jump


def test_guarded_return_inside_try_or_loop_counts():
    body = [{"k": "try", "body": [_if([_ret()])], "catches": [], "finally": [], "line": 1}, assign("o", "B", lit(2))]
    assert _cond_flags(body) == [("B", True)]
    body = [{"k": "loop", "body": [_if([_ret()])], "line": 1}, assign("o", "B", lit(2))]
    assert _cond_flags(body) == [("B", True)]


def test_unconditional_trailing_return_changes_nothing():
    assert _cond_flags([assign("o", "A", lit(1)), _ret()]) == [("A", False)]


def test_return_in_nested_lambda_does_not_count():
    inner = lam(["x"], [_if([_ret()])])
    body = [{"k": "expr", "e": call(name("list"), "Select", [inner]), "line": 1}, assign("o", "B", lit(2))]
    assert _cond_flags(body) == [("B", False)]


def test_switch_sections_lower_to_conditional_ifs():
    body = [_if([assign("o", "A", lit(1))]), _if([assign("o", "A", lit(2))])]
    assert _cond_flags(body) == [("A", True), ("A", True)]


def test_verdict_uncertain_but_no_bad_value_keeps_last():
    body = [assign("o", "A", lit(1)), _if([assign("o", "A", lit(2))])]
    opts = assignments(lam(["o"], body))
    o, uncertain = verdict(opts, "A", bad=lambda x: const(x.value) == 99)
    assert uncertain is True and o.value["v"] == 2


# -- opaque_reason -----------------------------------------------------------

def _opaque(*args, named=None):
    from checks.dnl.options import opaque_reason
    return opaque_reason(call(None, "AddCookie", list(args), named))


def test_opaque_no_args_and_scheme_names_are_not_opaque():
    assert _opaque() is None
    assert _opaque(lit("Cookies")) is None
    assert _opaque(member(name("CookieAuthenticationDefaults"), "AuthenticationScheme")) is None


def test_opaque_readable_lambda_and_new_are_not_opaque():
    assert _opaque(lam(["o"], [assign("o", "Cookie.HttpOnly", lit(False))])) is None
    assert _opaque(lit("Cookies"), lam(["o"], assign("o", "Cookie.HttpOnly", lit(False)))) is None
    assert _opaque({"k": "new", "type": "CookiePolicyOptions", "args": [], "init": [], "line": 1}) is None


def test_opaque_method_group_variable_and_config_section():
    assert _opaque(name("ConfigureCookie"))
    assert _opaque(name("policyVar"))
    assert _opaque(call(member(name("builder"), "Configuration"), "GetSection", [lit("Cookie")]))


def test_opaque_option_parameter_escapes():
    helper = lam(["o"], [{"k": "expr", "e": call(None, "Configure", [name("o")]), "line": 1}])
    assert _opaque(helper)
    assert _opaque(lam(["o"], call(None, "Harden", [member(name("o"), "Cookie")])))
    assert _opaque(lam(["o"], [{"k": "local", "name": "c", "init": name("o"), "line": 1}]))
    assert _opaque(lam(["o"], [{"k": "return", "value": name("o"), "line": 1}]))


def test_opaque_lambda_that_only_sets_members_is_fine():
    assert _opaque(lam(["o"], [assign("o", "Cookie.Name", name("cfgName"))])) is None
    shadow = lam(["o"], [{"k": "expr", "e": call(None, "Each", [lam(["o"], call(None, "F", [name("o")]))]), "line": 1}])
    assert _opaque(shadow) is None


def test_opaque_method_group_on_a_defaults_class_is_opaque():
    assert _opaque(member(name("AuthDefaults"), "ConfigureCookie"))
    assert _opaque(member(name("CookieDefaults"), "Configure"))
    assert _opaque(member(name("CookieAuthenticationDefaults"), "ConfigureCookie"))


def test_opaque_known_scheme_constants_are_not_opaque():
    for obj, n in (("CookieAuthenticationDefaults", "AuthenticationScheme"), ("JwtBearerDefaults", "AuthenticationScheme"),
                   ("Custom", "AuthenticationScheme"), ("IdentityConstants", "ApplicationScheme"),
                   ("IdentityConstants", "ExternalScheme"), ("IdentityConstants", "TwoFactorRememberMeScheme"),
                   ("IdentityConstants", "TwoFactorUserIdScheme")):
        assert _opaque(member(name(obj), n)) is None, (obj, n)
    assert _opaque(call(None, "nameof", [name("X")])) is None


def test_opaque_bare_name_is_opaque():
    assert _opaque(name("SchemeName"))
    assert _opaque(lit("Cookies"), name("SchemeName"))


def test_opaque_known_limit_wrapped_expression_is_not_detected():
    # Known limit: the options parameter inside a wrapping expression (`Harden(o.Cookie ?? fallback)`) is
    # not seen as handed off. Pinned so a change is deliberate.
    wrapped = {"k": "bin", "op": "??", "l": member(name("o"), "Cookie"), "r": name("fallback"), "line": 1}
    assert _opaque(lam(["o"], call(None, "Harden", [wrapped]))) is None
