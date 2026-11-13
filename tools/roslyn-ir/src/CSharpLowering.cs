using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace RoslynIr;

/// <summary>
/// Lowers one C# syntax tree to schema-1 FileIR. A CSharpSyntaxWalker finds
/// the type declarations (nested ones flattened to "Outer.Inner"); members,
/// statements and expressions are then lowered recursively. Anything without
/// a mapping becomes other/unknown carrying its source text -- this class
/// never throws on an unfamiliar node kind.
///
/// Semantic annotation (optional "sym" on call/member, "type_full" on
/// new/local) comes from a per-tree Semantics over the project compilation;
/// with none, or when a symbol does not resolve, the keys are omitted and
/// the IR is exactly the syntactic one.
/// </summary>
internal sealed class CSharpLowering
{
    static readonly CSharpParseOptions ParseOptions =
        new(LanguageVersion.Latest, DocumentationMode.None);

    readonly IrWriter w;
    readonly SourceText text;
    readonly Semantics? sem;

    // Receivers of enclosing ?. / ?[ ] accesses, resolved by member/element bindings.
    readonly Stack<ExpressionSyntax> receivers = new();

    CSharpLowering(IrWriter w, SourceText text, Semantics? sem)
    {
        this.w = w;
        this.text = text;
        this.sem = sem;
    }

    public static SyntaxTree Parse(string source, string path) =>
        CSharpSyntaxTree.ParseText(SourceText.From(source), ParseOptions, path);

    public static void WriteFile(IrWriter w, string path, string project, SyntaxTree tree, Semantics? sem)
    {
        var text = tree.GetText();
        var root = (CompilationUnitSyntax)tree.GetRoot();
        int errors = tree.GetDiagnostics().Count(d => d.Severity == DiagnosticSeverity.Error);

        var collector = new TypeCollector();
        collector.Visit(root);

        var lowering = new CSharpLowering(w, text, sem);
        w.BeginFile(path, "cs", project, errors);
        foreach (var (node, ns, name) in collector.Found)
            lowering.Type(node, ns, name);
        w.EndFile();
    }

    // -- positions --------------------------------------------------------

    int Line(SyntaxNode n) => text.Lines.GetLineFromPosition(n.SpanStart).LineNumber + 1;

    int LineOf(SyntaxToken t) => text.Lines.GetLineFromPosition(t.SpanStart).LineNumber + 1;

    int EndLine(SyntaxNode n) =>
        text.Lines.GetLineFromPosition(Math.Max(n.SpanStart, n.Span.End - 1)).LineNumber + 1;

    /// <summary>Declaration line: first token after any attribute lists.</summary>
    int DeclLine(SyntaxNode node, SyntaxList<AttributeListSyntax> attrs)
    {
        if (attrs.Count == 0) return Line(node);
        var next = attrs[attrs.Count - 1].GetLastToken().GetNextToken();
        return next.IsKind(SyntaxKind.None) ? Line(node) : LineOf(next);
    }

    static string? Id(SyntaxToken t) =>
        t.IsKind(SyntaxKind.None) || t.ValueText.Length == 0 ? null : t.ValueText;

    /// <summary>Rightmost identifier of a type name, without type arguments.</summary>
    static string SimpleName(TypeSyntax t) => t switch
    {
        IdentifierNameSyntax i => i.Identifier.ValueText,
        GenericNameSyntax g => g.Identifier.ValueText,
        QualifiedNameSyntax q => SimpleName(q.Right),
        AliasQualifiedNameSyntax a => SimpleName(a.Name),
        _ => t.ToString(),
    };

    // -- types and members --------------------------------------------------

    void Type(BaseTypeDeclarationSyntax node, string ns, string name)
    {
        var j = w.J;
        j.WriteStartObject();
        w.Str("name", name);
        w.Str("namespace", ns);
        w.Str("kind", node switch
        {
            StructDeclarationSyntax => "struct",
            InterfaceDeclarationSyntax => "interface",
            EnumDeclarationSyntax => "enum",
            RecordDeclarationSyntax r when r.ClassOrStructKeyword.IsKind(SyntaxKind.StructKeyword) => "struct",
            _ => "class",
        });
        w.StrArray("modifiers", IrWriter.NormalizeModifiers(node.Modifiers.Select(m => m.ValueText), vb: false));
        w.StrArray("bases", node.BaseList?.Types.Select(b => SimpleName(b.Type)) ?? []);
        Attributes("attributes", node.AttributeLists);

        var members = node is TypeDeclarationSyntax td ? td.Members : default;

        j.WriteStartArray("fields");
        if (node is EnumDeclarationSyntax en)
        {
            // Enum members surface as const fields typed by the enum itself.
            foreach (var m in en.Members)
            {
                j.WriteStartObject();
                w.Str("name", m.Identifier.ValueText);
                w.Str("type", en.Identifier.ValueText);
                j.WriteNumber("line", Line(m));
                ExprProp("init", m.EqualsValue?.Value);
                j.WriteBoolean("is_const", true);
                j.WriteEndObject();
            }
        }
        foreach (var f in members.OfType<FieldDeclarationSyntax>())
        {
            bool isConst = f.Modifiers.Any(SyntaxKind.ConstKeyword);
            string type = f.Declaration.Type.ToString();
            foreach (var v in f.Declaration.Variables)
            {
                j.WriteStartObject();
                w.Str("name", v.Identifier.ValueText);
                w.Str("type", type);
                j.WriteNumber("line", Line(v));
                ExprProp("init", v.Initializer?.Value);
                j.WriteBoolean("is_const", isConst);
                j.WriteEndObject();
            }
        }
        j.WriteEndArray();

        j.WriteStartArray("properties");
        foreach (var p in members.OfType<PropertyDeclarationSyntax>())
        {
            j.WriteStartObject();
            w.Str("name", p.Identifier.ValueText);
            w.Str("type", p.Type.ToString());
            Attributes("attributes", p.AttributeLists);
            Accessors(p);
            // `{ get; set; } = expr` initializer (auto-properties only).
            if (p.Initializer?.Value is { } pinit) ExprProp("init", pinit);
            j.WriteNumber("line", DeclLine(p, p.AttributeLists));
            j.WriteEndObject();
        }
        j.WriteEndArray();

        j.WriteStartArray("methods");
        foreach (var m in members)
        {
            switch (m)
            {
                case MethodDeclarationSyntax md:
                    Method(md, md.Identifier.ValueText, md.Modifiers, md.ReturnType.ToString(),
                        md.ParameterList, md.AttributeLists, md.Body, md.ExpressionBody, null,
                        returnsValue: !(md.ReturnType is PredefinedTypeSyntax pt && pt.Keyword.IsKind(SyntaxKind.VoidKeyword)),
                        implements: md.ExplicitInterfaceSpecifier is { } eis
                            ? [$"{eis.Name}.{md.Identifier.ValueText}"] : []);
                    break;
                case ConstructorDeclarationSyntax cd:
                    Method(cd, ".ctor", cd.Modifiers, null, cd.ParameterList, cd.AttributeLists,
                        cd.Body, cd.ExpressionBody, cd.Initializer, returnsValue: false);
                    break;
            }
        }
        j.WriteEndArray();

        j.WriteNumber("line", DeclLine(node, node.AttributeLists));
        j.WriteNumber("end_line", EndLine(node));
        j.WriteEndObject();
    }

    void Method(SyntaxNode node, string name, SyntaxTokenList modifiers, string? returnType,
        ParameterListSyntax parameters, SyntaxList<AttributeListSyntax> attrs, BlockSyntax? body,
        ArrowExpressionClauseSyntax? arrow, ConstructorInitializerSyntax? ctorInit, bool returnsValue,
        IEnumerable<string>? implements = null)
    {
        var j = w.J;
        j.WriteStartObject();
        w.Str("name", name);
        w.StrArray("modifiers", IrWriter.NormalizeModifiers(modifiers.Select(m => m.ValueText), vb: false));
        w.Str("return_type", returnType);

        j.WriteStartArray("params");
        foreach (var p in parameters.Parameters)
        {
            j.WriteStartObject();
            w.Str("name", p.Identifier.ValueText);
            w.Str("type", p.Type?.ToString());
            Attributes("attributes", p.AttributeLists);
            if (p.Modifiers.Count > 0) w.StrArray("modifiers", p.Modifiers.Select(m => m.ValueText.ToLowerInvariant()));
            j.WriteEndObject();
        }
        j.WriteEndArray();

        Attributes("attributes", attrs);
        w.StrArray("handles", []);
        w.StrArray("implements", implements ?? []);

        j.WriteStartArray("body");
        if (ctorInit is not null)
        {
            // ": base(x)" / ": this(x)" runs first; model it as a call statement.
            int l = Line(ctorInit);
            w.Begin("expr", l);
            j.WritePropertyName("expr");
            w.Begin("call", l);
            j.WritePropertyName("fn");
            w.Name(ctorInit.ThisOrBaseKeyword.IsKind(SyntaxKind.BaseKeyword) ? "base" : "this", l);
            Args(ctorInit.ArgumentList.Arguments);
            w.End();
            w.End();
        }
        if (body is not null) Seq(body.Statements);
        else if (arrow is not null)
        {
            if (returnsValue) Return(arrow.Expression, Line(arrow.Expression));
            else ExpressionStmt(arrow.Expression, Line(arrow.Expression));
        }
        j.WriteEndArray();

        j.WriteNumber("line", DeclLine(node, attrs));
        j.WriteNumber("end_line", EndLine(node));
        j.WriteEndObject();
    }

    /// <summary>Optional get/set Stmt lists: accessor blocks or expression
    /// bodies. "=> expr" lowers as get: [return expr]; auto-properties omit both.</summary>
    void Accessors(PropertyDeclarationSyntax p)
    {
        var j = w.J;
        if (p.ExpressionBody is { } arrow)
        {
            j.WriteStartArray("get");
            Return(arrow.Expression, Line(arrow.Expression));
            j.WriteEndArray();
            return;
        }
        if (p.AccessorList is null) return;
        foreach (var acc in p.AccessorList.Accessors)
        {
            string? key = acc.Keyword.Kind() switch
            {
                SyntaxKind.GetKeyword => "get",
                SyntaxKind.SetKeyword or SyntaxKind.InitKeyword => "set",
                _ => null,
            };
            if (key is null) continue;
            if (acc.Body is null && acc.ExpressionBody is null) continue;
            j.WriteStartArray(key);
            if (acc.Body is not null) Seq(acc.Body.Statements);
            else if (key == "get") Return(acc.ExpressionBody!.Expression, Line(acc.ExpressionBody.Expression));
            else ExpressionStmt(acc.ExpressionBody!.Expression, Line(acc.ExpressionBody.Expression));
            j.WriteEndArray();
        }
    }

    void Attributes(string prop, SyntaxList<AttributeListSyntax> lists)
    {
        var j = w.J;
        j.WriteStartArray(prop);
        foreach (var list in lists)
        {
            foreach (var a in list.Attributes)
            {
                j.WriteStartObject();
                w.Str("name", IrWriter.StripAttributeSuffix(SimpleName(a.Name)));
                var args = a.ArgumentList?.Arguments ?? default;
                j.WriteStartArray("args");
                foreach (var arg in args)
                    if (arg.NameEquals is null && arg.NameColon is null) Expr(arg.Expression);
                j.WriteEndArray();
                j.WriteStartObject("named");
                foreach (var arg in args)
                {
                    var key = arg.NameEquals?.Name.Identifier.ValueText ?? arg.NameColon?.Name.Identifier.ValueText;
                    if (key is null) continue;
                    j.WritePropertyName(IrWriter.Clean(key));
                    Expr(arg.Expression);
                }
                j.WriteEndObject();
                j.WriteNumber("line", Line(a));
                j.WriteEndObject();
            }
        }
        j.WriteEndArray();
    }

    // -- statements -----------------------------------------------------------

    /// <summary>Writes a statement list into the open array. "using var x = ...;"
    /// wraps the rest of the enclosing list as the using body.</summary>
    void Seq(IReadOnlyList<StatementSyntax> list, int start = 0)
    {
        for (int i = start; i < list.Count; i++)
        {
            if (list[i] is LocalDeclarationStatementSyntax ld && ld.UsingKeyword.IsKind(SyntaxKind.UsingKeyword))
            {
                w.Begin("using", Line(ld));
                w.J.WriteStartArray("resource");
                Locals(ld.Declaration);
                w.J.WriteEndArray();
                w.J.WriteStartArray("body");
                // Past the depth cap the fallback must cover every statement
                // it replaces: the rest of the block, not just this one.
                int rest = i + 1;
                if (rest < list.Count)
                    Nested(() => Seq(list, rest), Line(list[rest]),
                        () => text.ToString(TextSpan.FromBounds(list[rest].SpanStart, list[list.Count - 1].Span.End)));
                w.J.WriteEndArray();
                w.End();
                return;
            }
            Stmt(list[i]);
        }
    }

    static IReadOnlyList<StatementSyntax> AsList(StatementSyntax s) =>
        s is BlockSyntax b ? b.Statements : new[] { s };

    /// <summary>Runs a nested-body writer, or past the JSON depth cap emits one
    /// "other" whose text covers everything the writer would have lowered.</summary>
    void Nested(Action write, SyntaxNode fallback) =>
        Nested(write, Line(fallback), fallback.ToString);

    void Nested(Action write, int line, Func<string> fallbackText)
    {
        if (w.AtDepthCap) w.Text("other", line, fallbackText());
        else write();
    }

    void Body(string prop, StatementSyntax? s)
    {
        w.J.WriteStartArray(prop);
        if (s is not null) Nested(() => Seq(AsList(s)), s);
        w.J.WriteEndArray();
    }

    void Stmt(StatementSyntax s)
    {
        var j = w.J;
        int line = Line(s);
        switch (s)
        {
            case BlockSyntax b:
                Seq(b.Statements);
                break;
            case LocalDeclarationStatementSyntax ld:
                Locals(ld.Declaration);
                break;
            case ExpressionStatementSyntax es:
                ExpressionStmt(es.Expression, line);
                break;
            case ReturnStatementSyntax r:
                Return(r.Expression, line);
                break;
            case YieldStatementSyntax y when y.IsKind(SyntaxKind.YieldReturnStatement):
                Return(y.Expression, line);
                break;
            case ThrowStatementSyntax t:
                w.Begin("throw", line);
                ExprProp("value", t.Expression);
                w.End();
                break;
            case IfStatementSyntax ifs:
                w.Begin("if", line);
                ExprProp("cond", ifs.Condition);
                Body("then", ifs.Statement);
                Body("else", ifs.Else?.Statement);
                w.End();
                break;
            case ForEachStatementSyntax fe:
                w.Begin("loop", line);
                j.WriteStartArray("header");
                w.Name(fe.Identifier.ValueText, LineOf(fe.Identifier));
                Expr(fe.Expression);
                j.WriteEndArray();
                Body("body", fe.Statement);
                w.End();
                break;
            case ForEachVariableStatementSyntax fev:
                w.Begin("loop", line);
                j.WriteStartArray("header");
                Expr(fev.Variable);
                Expr(fev.Expression);
                j.WriteEndArray();
                Body("body", fev.Statement);
                w.End();
                break;
            case ForStatementSyntax f:
                w.Begin("loop", line);
                j.WriteStartArray("header");
                if (f.Declaration is not null)
                    foreach (var v in f.Declaration.Variables)
                        if (v.Initializer is not null) Expr(v.Initializer.Value);
                foreach (var e in f.Initializers) Expr(e);
                if (f.Condition is not null) Expr(f.Condition);
                foreach (var e in f.Incrementors) Expr(e);
                j.WriteEndArray();
                Body("body", f.Statement);
                w.End();
                break;
            case WhileStatementSyntax wh:
                Loop(line, wh.Condition, wh.Statement);
                break;
            case DoStatementSyntax d:
                Loop(line, d.Condition, d.Statement);
                break;
            case TryStatementSyntax t:
                w.Begin("try", line);
                Body("body", t.Block);
                j.WriteStartArray("catches");
                foreach (var c in t.Catches)
                {
                    j.WriteStartObject();
                    w.Str("type", c.Declaration?.Type.ToString());
                    w.Str("name", c.Declaration is null ? null : Id(c.Declaration.Identifier));
                    Body("body", c.Block);
                    j.WriteEndObject();
                }
                j.WriteEndArray();
                Body("finally", t.Finally?.Block);
                w.End();
                break;
            case UsingStatementSyntax u:
                w.Begin("using", line);
                j.WriteStartArray("resource");
                if (u.Declaration is not null) Locals(u.Declaration);
                else if (u.Expression is not null) ExpressionStmt(u.Expression, Line(u.Expression));
                j.WriteEndArray();
                Body("body", u.Statement);
                w.End();
                break;
            // Wrappers with no data-flow meaning of their own: inline the body.
            case LockStatementSyntax l:
                Seq(AsList(l.Statement));
                break;
            case CheckedStatementSyntax c:
                Seq(c.Block.Statements);
                break;
            case UnsafeStatementSyntax us:
                Seq(us.Block.Statements);
                break;
            case FixedStatementSyntax fx:
                Locals(fx.Declaration);
                Seq(AsList(fx.Statement));
                break;
            case LabeledStatementSyntax lb:
                Stmt(lb.Statement);
                break;
            case SwitchStatementSyntax sw:
                // One flat "if" per section (cond = the governing expression):
                // keeps case bodies visible without nesting depth per case.
                foreach (var sec in sw.Sections)
                {
                    w.Begin("if", Line(sec));
                    ExprProp("cond", sw.Expression);
                    j.WriteStartArray("then");
                    Nested(() => Seq(sec.Statements), sec);
                    j.WriteEndArray();
                    j.WriteStartArray("else");
                    j.WriteEndArray();
                    w.End();
                }
                break;
            case LocalFunctionStatementSyntax lf:
                // A local function is a named lambda.
                w.Begin("local", line);
                w.Str("name", lf.Identifier.ValueText);
                w.Str("type", lf.ReturnType.ToString());
                j.WritePropertyName("init");
                w.Begin("lambda", line);
                LambdaParams(lf.ParameterList.Parameters.Select(p => p.Identifier.ValueText));
                j.WritePropertyName("body");
                LambdaBody(lf.Body, lf.ExpressionBody?.Expression, lf);
                w.End();
                w.End();
                break;
            default:
                w.Text("other", line, s.ToString());
                break;
        }
    }

    void Loop(int line, ExpressionSyntax cond, StatementSyntax body)
    {
        w.Begin("loop", line);
        w.J.WriteStartArray("header");
        Expr(cond);
        w.J.WriteEndArray();
        Body("body", body);
        w.End();
    }

    void Locals(VariableDeclarationSyntax d)
    {
        string type = d.Type.ToString();
        foreach (var v in d.Variables)
        {
            w.Begin("local", Line(v));
            w.Str("name", v.Identifier.ValueText);
            w.Str("type", type);
            ExprProp("init", v.Initializer?.Value);
            w.OptStr("type_full", sem?.LocalType(v));
            w.End();
        }
    }

    void Return(ExpressionSyntax? value, int line)
    {
        w.Begin("return", line);
        ExprProp("value", value);
        w.End();
    }

    /// <summary>Expression used as a statement: assignments become assign, the rest expr.</summary>
    void ExpressionStmt(ExpressionSyntax e, int line)
    {
        if (e is AssignmentExpressionSyntax a)
        {
            w.Begin("assign", line);
            ExprProp("target", a.Left);
            if (a.IsKind(SyntaxKind.SimpleAssignmentExpression)) Assign("=", a.Right);
            else if (a.IsKind(SyntaxKind.AddAssignmentExpression)) Assign("+=", a.Right);
            else if (a.IsKind(SyntaxKind.SubtractAssignmentExpression)) Assign("-=", a.Right);
            else
            {
                // x *= y  ->  x = (x * y): keeps "op" within the schema's closed set.
                w.Str("op", "=");
                w.J.WritePropertyName("value");
                w.Begin("bin", Line(a));
                w.Str("op", a.OperatorToken.Text.TrimEnd('='));
                ExprProp("l", a.Left);
                ExprProp("r", a.Right);
                w.End();
            }
            w.End();
            return;
        }
        w.Begin("expr", line);
        ExprProp("expr", e);
        w.End();
    }

    void Assign(string op, ExpressionSyntax value)
    {
        w.Str("op", op);
        ExprProp("value", value);
    }

    // -- expressions ----------------------------------------------------------

    void ExprProp(string prop, ExpressionSyntax? e)
    {
        w.J.WritePropertyName(prop);
        Expr(e);
    }

    void Expr(ExpressionSyntax? e)
    {
        if (e is null)
        {
            w.J.WriteNullValue();
            return;
        }
        if (w.AtDepthCap) w.Text("unknown", Line(e), e.ToString());
        else ExprCore(e);
    }

    void ExprCore(ExpressionSyntax e)
    {
        var j = w.J;
        int line = Line(e);
        switch (e)
        {
            // Transparent wrappers: the value is the inner expression's.
            case ParenthesizedExpressionSyntax p: ExprCore(p.Expression); break;
            case AwaitExpressionSyntax aw: ExprCore(aw.Expression); break;
            case CheckedExpressionSyntax ch: ExprCore(ch.Expression); break;
            case RefExpressionSyntax rf: ExprCore(rf.Expression); break;
            case PostfixUnaryExpressionSyntax bang when bang.IsKind(SyntaxKind.SuppressNullableWarningExpression):
                ExprCore(bang.Operand);
                break;

            case LiteralExpressionSyntax lit:
                Literal(lit, line);
                break;
            case PrefixUnaryExpressionSyntax neg when neg.IsKind(SyntaxKind.UnaryMinusExpression)
                                                     && neg.Operand is LiteralExpressionSyntax num
                                                     && num.IsKind(SyntaxKind.NumericLiteralExpression):
                w.Lit(Negate(num.Token.Value), "number", line);
                break;

            case PrefixUnaryExpressionSyntax un when UnaryOp(un.Kind()) is { } op:
                w.Begin("unary", line);
                w.Str("op", op);
                ExprProp("e", un.Operand);
                w.End();
                break;
            case PostfixUnaryExpressionSyntax un when UnaryOp(un.Kind()) is { } op:
                w.Begin("unary", line);
                w.Str("op", op);
                ExprProp("e", un.Operand);
                w.End();
                break;

            case IdentifierNameSyntax id:
                w.Begin("name", line);
                w.Str("id", id.Identifier.ValueText);
                w.OptStr("sym", sem?.NameSym(id));
                w.End();
                break;
            case GenericNameSyntax g: w.Name(g.Identifier.ValueText, line); break;
            case PredefinedTypeSyntax pt: w.Name(pt.Keyword.ValueText, line); break;
            case ThisExpressionSyntax: w.Name("this", line); break;
            case BaseExpressionSyntax: w.Name("base", line); break;
            case QualifiedNameSyntax q:
                Member(q.Left, q.Right.Identifier.ValueText, line, q);
                break;
            case MemberAccessExpressionSyntax ma:
                Member(ma.Expression, ma.Name.Identifier.ValueText, line, ma);
                break;

            case ConditionalAccessExpressionSyntax ca:
                receivers.Push(ca.Expression);
                try { ExprCore(ca.WhenNotNull); }
                finally { receivers.Pop(); }
                break;
            case MemberBindingExpressionSyntax mb when receivers.Count > 0:
                WithReceiver(recv => Member(recv, mb.Name.Identifier.ValueText, line, mb));
                break;
            case ElementBindingExpressionSyntax eb when receivers.Count > 0:
                WithReceiver(recv => Index(recv, eb.ArgumentList.Arguments, line, eb));
                break;

            case InvocationExpressionSyntax inv:
                w.Begin("call", line);
                ExprProp("fn", inv.Expression);
                Args(inv.ArgumentList.Arguments);
                w.OptStr("sym", sem?.MemberSym(inv));
                w.End();
                break;
            case ElementAccessExpressionSyntax ea:
                Index(ea.Expression, ea.ArgumentList.Arguments, line, ea);
                break;

            case ObjectCreationExpressionSyntax oc:
                New(oc, oc.Type.ToString(), oc.ArgumentList?.Arguments, oc.Initializer, line);
                break;
            case ImplicitObjectCreationExpressionSyntax ioc:
                New(ioc, null, ioc.ArgumentList.Arguments, ioc.Initializer, line);
                break;
            case ArrayCreationExpressionSyntax ac:
                New(ac, ac.Type.ToString(), null, ac.Initializer, line);
                break;
            case ImplicitArrayCreationExpressionSyntax iac:
                New(iac, null, null, iac.Initializer, line);
                break;
            case InitializerExpressionSyntax ai when ai.IsKind(SyntaxKind.ArrayInitializerExpression):
                New(ai, null, null, ai, line);
                break;
            case AnonymousObjectCreationExpressionSyntax an:
                w.Begin("new", line);
                w.Str("type", null);
                j.WriteStartArray("args");
                j.WriteEndArray();
                j.WriteStartArray("init");
                foreach (var m in an.Initializers)
                    InitEntry(m.NameEquals?.Name.Identifier.ValueText ?? InferredName(m.Expression), m.Expression);
                j.WriteEndArray();
                w.End();
                break;

            case BinaryExpressionSyntax b when b.IsKind(SyntaxKind.AsExpression):
                Cast(b.Right.ToString(), b.Left, line);
                break;
            case BinaryExpressionSyntax b:
                w.Begin("bin", line);
                w.Str("op", b.OperatorToken.Text);
                ExprProp("l", b.Left);
                ExprProp("r", b.Right);
                w.End();
                break;

            case InterpolatedStringExpressionSyntax interp:
                w.Begin("interp", line);
                j.WriteStartArray("parts");
                foreach (var part in interp.Contents)
                {
                    if (part is InterpolatedStringTextSyntax ts)
                        w.Lit(ts.TextToken.ValueText, "string", Line(ts));
                    else if (part is InterpolationSyntax ip)
                        Expr(ip.Expression);
                }
                j.WriteEndArray();
                w.End();
                break;

            case ConditionalExpressionSyntax c:
                w.Begin("cond", line);
                ExprProp("c", c.Condition);
                ExprProp("t", c.WhenTrue);
                ExprProp("f", c.WhenFalse);
                w.End();
                break;
            case CastExpressionSyntax cast:
                Cast(cast.Type.ToString(), cast.Expression, line);
                break;

            case AnonymousFunctionExpressionSyntax fn:
                w.Begin("lambda", line);
                LambdaParams(fn switch
                {
                    SimpleLambdaExpressionSyntax sl => new[] { sl.Parameter.Identifier.ValueText },
                    ParenthesizedLambdaExpressionSyntax pl => pl.ParameterList.Parameters.Select(p => p.Identifier.ValueText),
                    AnonymousMethodExpressionSyntax am when am.ParameterList is not null =>
                        am.ParameterList.Parameters.Select(p => p.Identifier.ValueText),
                    _ => [],
                });
                j.WritePropertyName("body");
                LambdaBody(fn.Block, fn.ExpressionBody, fn);
                w.End();
                break;

            default:
                w.Text("unknown", line, e.ToString());
                break;
        }
    }

    /// <summary>Lowers a ?. receiver with the binding stack rewound one level,
    /// so chained a?.b?.c resolves each binding against its own receiver.</summary>
    void WithReceiver(Action<ExpressionSyntax> write)
    {
        var recv = receivers.Pop();
        try { write(recv); }
        finally { receivers.Push(recv); }
    }

    /// <summary>member node; symNode is the syntax the symbol binds to (the
    /// access itself, or the ?. member binding).</summary>
    void Member(ExpressionSyntax obj, string name, int line, ExpressionSyntax symNode)
    {
        w.Begin("member", line);
        ExprProp("obj", obj);
        w.Str("name", name);
        w.OptStr("sym", sem?.MemberSym(symNode));
        w.End();
    }

    static string? UnaryOp(SyntaxKind k) => k switch
    {
        SyntaxKind.LogicalNotExpression => "!",
        SyntaxKind.UnaryMinusExpression => "-",
        SyntaxKind.BitwiseNotExpression => "~",
        SyntaxKind.PreIncrementExpression or SyntaxKind.PostIncrementExpression => "++",
        SyntaxKind.PreDecrementExpression or SyntaxKind.PostDecrementExpression => "--",
        _ => null,
    };

    void Index(ExpressionSyntax obj, SeparatedSyntaxList<ArgumentSyntax> args, int line, ExpressionSyntax symNode)
    {
        w.Begin("index", line);
        ExprProp("obj", obj);
        w.J.WriteStartArray("args");
        foreach (var a in args) Expr(a.Expression);
        w.J.WriteEndArray();
        w.OptStr("sym", sem?.IndexSym(symNode));
        w.End();
    }

    void Cast(string type, ExpressionSyntax e, int line)
    {
        w.Begin("cast", line);
        w.Str("type", type);
        ExprProp("e", e);
        w.End();
    }

    /// <summary>Positional args to "args", name: args to "named".</summary>
    void Args(SeparatedSyntaxList<ArgumentSyntax> args)
    {
        var j = w.J;
        j.WriteStartArray("args");
        foreach (var a in args)
            if (a.NameColon is null) Expr(a.Expression);
        j.WriteEndArray();
        j.WriteStartObject("named");
        foreach (var a in args)
        {
            if (a.NameColon is null) continue;
            j.WritePropertyName(IrWriter.Clean(a.NameColon.Name.Identifier.ValueText));
            Expr(a.Expression);
        }
        j.WriteEndObject();
    }

    void New(ExpressionSyntax node, string? type, SeparatedSyntaxList<ArgumentSyntax>? args,
        InitializerExpressionSyntax? init, int line)
    {
        var j = w.J;
        w.Begin("new", line);
        w.Str("type", type);
        j.WriteStartArray("args");
        if (args is { } list)
            foreach (var a in list) Expr(a.Expression);
        j.WriteEndArray();
        j.WriteStartArray("init");
        if (init is not null)
        {
            foreach (var e in init.Expressions)
            {
                // { A = 1 } carries a member name; collection/array elements do not.
                if (e is AssignmentExpressionSyntax a && a.IsKind(SyntaxKind.SimpleAssignmentExpression))
                    InitEntry(a.Left is IdentifierNameSyntax n ? n.Identifier.ValueText : a.Left.ToString(), a.Right);
                else
                    InitEntry(null, e);
            }
        }
        j.WriteEndArray();
        w.OptStr("type_full", sem?.ExprType(node));
        w.End();
    }

    void InitEntry(string? name, ExpressionSyntax value)
    {
        w.J.WriteStartObject();
        w.Str("name", name);
        ExprProp("value", value);
        w.J.WriteEndObject();
    }

    static string? InferredName(ExpressionSyntax e) => e switch
    {
        IdentifierNameSyntax i => i.Identifier.ValueText,
        MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
        _ => null,
    };

    /// <summary>Lambda body: Stmt list for a block (or an assignment expression), else a single Expr.</summary>
    /// <summary>Optional `params` key of a lambda: its parameter names, omitted when it has none.</summary>
    void LambdaParams(IEnumerable<string> names)
    {
        var list = names.ToList();
        if (list.Count > 0) w.StrArray("params", list);
    }

    void LambdaBody(BlockSyntax? block, ExpressionSyntax? expr, SyntaxNode fallback)
    {
        if (block is null && expr is not null && expr is not AssignmentExpressionSyntax)
        {
            Expr(expr);
            return;
        }
        w.J.WriteStartArray();
        Nested(() =>
        {
            if (block is not null) Seq(block.Statements);
            else if (expr is not null) ExpressionStmt(expr, Line(expr));
        }, fallback);
        w.J.WriteEndArray();
    }

    void Literal(LiteralExpressionSyntax lit, int line)
    {
        if (lit.IsKind(SyntaxKind.StringLiteralExpression) || lit.IsKind(SyntaxKind.Utf8StringLiteralExpression))
            w.Lit(lit.Token.ValueText, "string", line);
        else if (lit.IsKind(SyntaxKind.CharacterLiteralExpression))
            w.Lit(lit.Token.Value, "char", line);
        else if (lit.IsKind(SyntaxKind.NumericLiteralExpression))
            w.Lit(lit.Token.Value, "number", line);
        else if (lit.IsKind(SyntaxKind.TrueLiteralExpression))
            w.Lit(true, "bool", line);
        else if (lit.IsKind(SyntaxKind.FalseLiteralExpression))
            w.Lit(false, "bool", line);
        else if (lit.IsKind(SyntaxKind.NullLiteralExpression))
            w.Lit(null, "null", line);
        else
            w.Text("unknown", line, lit.ToString()); // default, __arglist, ...
    }

    internal static object? Negate(object? v) => v switch
    {
        int i => -(long)i,
        long l => -l,
        uint ui => -(long)ui,
        ulong ul => -(decimal)ul,
        float f => -f,
        double d => -d,
        decimal m => -m,
        _ => v,
    };

    // -- type discovery -------------------------------------------------------

    /// <summary>Collects type declarations in document order (outer before
    /// inner) with their namespace and dotted nesting name.</summary>
    sealed class TypeCollector : CSharpSyntaxWalker
    {
        public readonly List<(BaseTypeDeclarationSyntax Node, string Namespace, string Name)> Found = [];
        readonly List<string> ns = [];
        readonly List<string> outer = [];

        public override void VisitNamespaceDeclaration(NamespaceDeclarationSyntax node)
        {
            ns.Add(node.Name.ToString());
            base.VisitNamespaceDeclaration(node);
            ns.RemoveAt(ns.Count - 1);
        }

        public override void VisitFileScopedNamespaceDeclaration(FileScopedNamespaceDeclarationSyntax node)
        {
            ns.Add(node.Name.ToString());
            base.VisitFileScopedNamespaceDeclaration(node);
            ns.RemoveAt(ns.Count - 1);
        }

        public override void VisitClassDeclaration(ClassDeclarationSyntax node) =>
            Add(node, () => base.VisitClassDeclaration(node));

        public override void VisitStructDeclaration(StructDeclarationSyntax node) =>
            Add(node, () => base.VisitStructDeclaration(node));

        public override void VisitInterfaceDeclaration(InterfaceDeclarationSyntax node) =>
            Add(node, () => base.VisitInterfaceDeclaration(node));

        public override void VisitRecordDeclaration(RecordDeclarationSyntax node) =>
            Add(node, () => base.VisitRecordDeclaration(node));

        public override void VisitEnumDeclaration(EnumDeclarationSyntax node) => Add(node, () => { });

        // Bodies and initializers never declare types: skip them.
        public override void VisitBlock(BlockSyntax node) { }
        public override void VisitArrowExpressionClause(ArrowExpressionClauseSyntax node) { }
        public override void VisitEqualsValueClause(EqualsValueClauseSyntax node) { }

        void Add(BaseTypeDeclarationSyntax node, Action descend)
        {
            string id = node.Identifier.ValueText;
            Found.Add((node, string.Join(".", ns), string.Join(".", outer.Append(id))));
            outer.Add(id);
            descend();
            outer.RemoveAt(outer.Count - 1);
        }
    }
}
