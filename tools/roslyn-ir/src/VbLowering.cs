using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.VisualBasic;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace RoslynIr;

/// <summary>
/// Lowers one VB.NET syntax tree to schema-1 FileIR, mirroring CSharpLowering
/// so both languages produce the same shapes. VB specifics: "&amp;" lowers to
/// bin op "concat", "&amp;=" to assign op "concat=", Me/MyBase/MyClass to
/// this/base/this, "Handles x.Y" fills Method.handles, and a member access
/// with no receiver inside a With block has "obj": null (the With target).
/// x(1) stays a call (VB cannot tell indexing from invocation syntactically).
///
/// Semantic keys ("sym" on call/member, "type_full" on new/local) come from
/// an optional per-tree Semantics, exactly as in CSharpLowering.
/// </summary>
internal sealed class VbLowering
{
    static readonly VisualBasicParseOptions ParseOptions =
        new(LanguageVersion.Latest, DocumentationMode.None);

    // CStr(x) etc: the conversion keyword names its target type.
    static readonly Dictionary<string, string> PredefinedCasts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CBool"] = "Boolean", ["CByte"] = "Byte", ["CChar"] = "Char", ["CDate"] = "Date",
        ["CDbl"] = "Double", ["CDec"] = "Decimal", ["CInt"] = "Integer", ["CLng"] = "Long",
        ["CObj"] = "Object", ["CSByte"] = "SByte", ["CShort"] = "Short", ["CSng"] = "Single",
        ["CStr"] = "String", ["CUInt"] = "UInteger", ["CULng"] = "ULong", ["CUShort"] = "UShort",
    };

    readonly IrWriter w;
    readonly SourceText text;
    readonly Semantics? sem;

    // ?. bindings: the receiver-less node at the left end of a WhenNotNull
    // chain, mapped to the ConditionalAccess receiver it binds to.
    readonly Dictionary<SyntaxNode, ExpressionSyntax> bindings = [];

    VbLowering(IrWriter w, SourceText text, Semantics? sem)
    {
        this.w = w;
        this.text = text;
        this.sem = sem;
    }

    public static SyntaxTree Parse(string source, string path) =>
        VisualBasicSyntaxTree.ParseText(SourceText.From(source), ParseOptions, path);

    public static void WriteFile(IrWriter w, string path, string project, SyntaxTree tree, Semantics? sem)
    {
        var text = tree.GetText();
        var root = tree.GetRoot();
        int errors = tree.GetDiagnostics().Count(d => d.Severity == DiagnosticSeverity.Error);

        var collector = new TypeCollector();
        collector.Visit(root);

        var lowering = new VbLowering(w, text, sem);
        w.BeginFile(path, "vb", project, errors);
        foreach (var (node, ns, name) in collector.Found)
            lowering.Type(node, ns, name);
        w.EndFile();
    }

    // -- positions --------------------------------------------------------

    int Line(SyntaxNode n) => text.Lines.GetLineFromPosition(n.SpanStart).LineNumber + 1;

    int LineOf(SyntaxToken t) => text.Lines.GetLineFromPosition(t.SpanStart).LineNumber + 1;

    int EndLine(SyntaxNode n) =>
        text.Lines.GetLineFromPosition(Math.Max(n.SpanStart, n.Span.End - 1)).LineNumber + 1;

    int DeclLine(SyntaxNode node, SyntaxList<AttributeListSyntax> attrs)
    {
        if (attrs.Count == 0) return Line(node);
        var next = attrs[attrs.Count - 1].GetLastToken().GetNextToken();
        return next.IsKind(SyntaxKind.None) ? Line(node) : LineOf(next);
    }

    static string SimpleName(TypeSyntax t) => t switch
    {
        IdentifierNameSyntax i => i.Identifier.ValueText,
        GenericNameSyntax g => g.Identifier.ValueText,
        QualifiedNameSyntax q => SimpleName(q.Right),
        _ => t.ToString(),
    };

    static List<string> Modifiers(SyntaxTokenList mods) =>
        IrWriter.NormalizeModifiers(mods.Select(m => m.ValueText), vb: true);

    static string? AsType(AsClauseSyntax? clause) => clause switch
    {
        SimpleAsClauseSyntax s => s.Type.ToString(),
        AsNewClauseSyntax { NewExpression: ObjectCreationExpressionSyntax oc } => oc.Type.ToString(),
        _ => null,
    };

    /// <summary>Initializer of a declarator: "= value" or the "As New T(...)" expression.</summary>
    static ExpressionSyntax? DeclInit(VariableDeclaratorSyntax d) =>
        d.Initializer?.Value ?? (d.AsClause as AsNewClauseSyntax)?.NewExpression;

    // -- types and members --------------------------------------------------

    void Type(DeclarationStatementSyntax node, string ns, string name)
    {
        var j = w.J;
        var (stmt, kind) = node switch
        {
            ClassBlockSyntax c => ((DeclarationStatementSyntax)c.BlockStatement, "class"),
            StructureBlockSyntax s => (s.BlockStatement, "struct"),
            InterfaceBlockSyntax i => (i.BlockStatement, "interface"),
            ModuleBlockSyntax m => (m.BlockStatement, "module"),
            EnumBlockSyntax e => (e.EnumStatement, "enum"),
            _ => (node, "class"),
        };
        var (mods, attrs) = stmt switch
        {
            TypeStatementSyntax ts => (ts.Modifiers, ts.AttributeLists),
            EnumStatementSyntax es => (es.Modifiers, es.AttributeLists),
            _ => (default(SyntaxTokenList), default(SyntaxList<AttributeListSyntax>)),
        };

        j.WriteStartObject();
        w.Str("name", name);
        w.Str("namespace", ns);
        w.Str("kind", kind);
        w.StrArray("modifiers", Modifiers(mods));

        var tb = node as TypeBlockSyntax;
        var bases = tb is null
            ? []
            : tb.Inherits.SelectMany(i => i.Types).Concat(tb.Implements.SelectMany(i => i.Types)).Select(SimpleName);
        w.StrArray("bases", bases);
        Attributes("attributes", attrs);

        var members = tb?.Members ?? default;

        j.WriteStartArray("fields");
        if (node is EnumBlockSyntax en)
        {
            foreach (var m in en.Members.OfType<EnumMemberDeclarationSyntax>())
            {
                j.WriteStartObject();
                w.Str("name", m.Identifier.ValueText);
                w.Str("type", en.EnumStatement.Identifier.ValueText);
                j.WriteNumber("line", Line(m));
                ExprProp("init", m.Initializer?.Value);
                j.WriteBoolean("is_const", true);
                j.WriteEndObject();
            }
        }
        foreach (var f in members.OfType<FieldDeclarationSyntax>())
        {
            bool isConst = f.Modifiers.Any(SyntaxKind.ConstKeyword);
            foreach (var d in f.Declarators)
            {
                foreach (var n in d.Names)
                {
                    j.WriteStartObject();
                    w.Str("name", n.Identifier.ValueText);
                    w.Str("type", AsType(d.AsClause));
                    j.WriteNumber("line", Line(n));
                    ExprProp("init", DeclInit(d));
                    j.WriteBoolean("is_const", isConst);
                    j.WriteEndObject();
                }
            }
        }
        j.WriteEndArray();

        j.WriteStartArray("properties");
        foreach (var m in members)
        {
            var p = m switch
            {
                PropertyStatementSyntax ps => ps,
                PropertyBlockSyntax pb => pb.PropertyStatement,
                _ => null,
            };
            if (p is null) continue;
            var accessors = (m as PropertyBlockSyntax)?.Accessors ?? default;
            j.WriteStartObject();
            w.Str("name", p.Identifier.ValueText);
            w.Str("type", AsType(p.AsClause));
            Attributes("attributes", p.AttributeLists);
            // Optional get/set Stmt lists from Property Get/Set blocks; an
            // auto-property has no block and omits both.
            foreach (var acc in accessors)
            {
                string? key = acc.Kind() switch
                {
                    SyntaxKind.GetAccessorBlock => "get",
                    SyntaxKind.SetAccessorBlock => "set",
                    _ => null,
                };
                if (key is null) continue;
                j.WriteStartArray(key);
                Seq(acc.Statements);
                j.WriteEndArray();
                // The setter's value parameter keeps its declared name (default `Value`).
                if (key == "set")
                    w.Str("set_param", acc.AccessorStatement.ParameterList?.Parameters.FirstOrDefault()?.Identifier.Identifier.ValueText ?? "Value");
            }
            // `Property X As String = "..."` / `As New T(...)` initializer.
            if ((p.Initializer?.Value ?? (p.AsClause as AsNewClauseSyntax)?.NewExpression) is { } pinit)
                ExprProp("init", pinit);
            j.WriteNumber("line", DeclLine(p, p.AttributeLists));
            j.WriteEndObject();
        }
        j.WriteEndArray();

        j.WriteStartArray("methods");
        foreach (var m in members)
        {
            switch (m)
            {
                case MethodBlockSyntax mb:
                    Method(mb, mb.SubOrFunctionStatement, mb.Statements);
                    break;
                case ConstructorBlockSyntax cb:
                    Method(cb, cb.SubNewStatement, cb.Statements);
                    break;
                case MethodStatementSyntax ms: // MustOverride or interface member: no body
                    Method(ms, ms, null);
                    break;
            }
        }
        j.WriteEndArray();

        j.WriteNumber("line", DeclLine(stmt, attrs));
        j.WriteNumber("end_line", EndLine(node));
        j.WriteEndObject();
    }

    void Method(SyntaxNode node, MethodBaseSyntax sig, SyntaxList<StatementSyntax>? body)
    {
        var j = w.J;
        string name;
        string? returnType;
        IEnumerable<string> handles = [];
        IEnumerable<string> implements = [];
        if (sig is MethodStatementSyntax ms)
        {
            name = ms.Identifier.ValueText;
            returnType = ms.IsKind(SyntaxKind.SubStatement) ? "void" : ms.AsClause?.Type.ToString() ?? "Object";
            if (ms.HandlesClause is not null)
                handles = ms.HandlesClause.Events.Select(e => e.ToString());
            if (ms.ImplementsClause is not null)
                implements = ms.ImplementsClause.InterfaceMembers.Select(m => m.ToString());
        }
        else
        {
            name = ".ctor";
            returnType = null;
        }

        j.WriteStartObject();
        w.Str("name", name);
        w.StrArray("modifiers", Modifiers(sig.Modifiers));
        w.Str("return_type", returnType);

        j.WriteStartArray("params");
        foreach (var p in sig.ParameterList?.Parameters ?? default)
        {
            j.WriteStartObject();
            w.Str("name", p.Identifier.Identifier.ValueText);
            w.Str("type", p.AsClause?.Type.ToString() ?? "Object");
            Attributes("attributes", p.AttributeLists);
            if (p.Modifiers.Count > 0) w.StrArray("modifiers", p.Modifiers.Select(m => m.ValueText.ToLowerInvariant()));
            j.WriteEndObject();
        }
        j.WriteEndArray();

        Attributes("attributes", sig.AttributeLists);
        w.StrArray("handles", handles);
        w.StrArray("implements", implements);

        j.WriteStartArray("body");
        if (body is { } stmts) Seq(stmts);
        j.WriteEndArray();

        j.WriteNumber("line", DeclLine(sig, sig.AttributeLists));
        j.WriteNumber("end_line", EndLine(node));
        j.WriteEndObject();
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
                Args(args);
                j.WriteNumber("line", Line(a));
                j.WriteEndObject();
            }
        }
        j.WriteEndArray();
    }

    // -- statements -----------------------------------------------------------

    void Seq(SyntaxList<StatementSyntax> list)
    {
        foreach (var s in list) Stmt(s);
    }

    /// <summary>Runs a nested-body writer, or past the JSON depth cap emits one
    /// "other" whose text covers everything the writer would have lowered.</summary>
    void Nested(Action write, SyntaxNode fallback) =>
        Nested(write, Line(fallback), fallback.ToString);

    void Nested(Action write, int line, Func<string> fallbackText)
    {
        if (w.AtDepthCap) w.Text("other", line, fallbackText());
        else write();
    }

    /// <summary>Optional `params` key of a lambda: its parameter names, omitted when it has none.</summary>
    void LambdaParams(ParameterListSyntax? list)
    {
        var names = (list?.Parameters ?? default).Select(p => p.Identifier.Identifier.ValueText).ToList();
        if (names.Count > 0) w.StrArray("params", names);
    }

    void Body(string prop, SyntaxList<StatementSyntax> list, SyntaxNode fallback)
    {
        w.J.WriteStartArray(prop);
        if (list.Count > 0) Nested(() => Seq(list), fallback);
        w.J.WriteEndArray();
    }

    void Stmt(StatementSyntax s)
    {
        var j = w.J;
        int line = Line(s);
        switch (s)
        {
            case LocalDeclarationStatementSyntax ld:
                Locals(ld.Declarators);
                break;
            case AssignmentStatementSyntax a:
                AssignStmt(a, line);
                break;
            case ExpressionStatementSyntax es:
                ExprStmt(es.Expression, line);
                break;
            case CallStatementSyntax cs:
                ExprStmt(cs.Invocation, line);
                break;
            case ReturnStatementSyntax r:
                w.Begin("return", line);
                ExprProp("value", r.Expression);
                w.End();
                break;
            case ThrowStatementSyntax t:
                w.Begin("throw", line);
                ExprProp("value", t.Expression);
                w.End();
                break;
            case MultiLineIfBlockSyntax mi:
                IfChain(line, mi.IfStatement.Condition, mi.Statements, mi, mi.ElseIfBlocks, 0, mi.ElseBlock);
                break;
            case SingleLineIfStatementSyntax si:
                w.Begin("if", line);
                ExprProp("cond", si.Condition);
                Body("then", si.Statements, si);
                Body("else", si.ElseClause?.Statements ?? default, si);
                w.End();
                break;
            case ForBlockSyntax fb:
                w.Begin("loop", line);
                j.WriteStartArray("header");
                ControlVariable(fb.ForStatement.ControlVariable);
                Expr(fb.ForStatement.FromValue);
                Expr(fb.ForStatement.ToValue);
                if (fb.ForStatement.StepClause is not null) Expr(fb.ForStatement.StepClause.StepValue);
                j.WriteEndArray();
                Body("body", fb.Statements, fb);
                w.End();
                break;
            case ForEachBlockSyntax feb:
                w.Begin("loop", line);
                j.WriteStartArray("header");
                ControlVariable(feb.ForEachStatement.ControlVariable);
                Expr(feb.ForEachStatement.Expression);
                j.WriteEndArray();
                Body("body", feb.Statements, feb);
                w.End();
                break;
            case WhileBlockSyntax wb:
                w.Begin("loop", line);
                j.WriteStartArray("header");
                Expr(wb.WhileStatement.Condition);
                j.WriteEndArray();
                Body("body", wb.Statements, wb);
                w.End();
                break;
            case DoLoopBlockSyntax db:
                w.Begin("loop", line);
                j.WriteStartArray("header");
                if (db.DoStatement.WhileOrUntilClause is { } top) Expr(top.Condition);
                if (db.LoopStatement.WhileOrUntilClause is { } bottom) Expr(bottom.Condition);
                j.WriteEndArray();
                Body("body", db.Statements, db);
                w.End();
                break;
            case TryBlockSyntax tb:
                w.Begin("try", line);
                Body("body", tb.Statements, tb);
                j.WriteStartArray("catches");
                foreach (var c in tb.CatchBlocks)
                {
                    j.WriteStartObject();
                    w.Str("type", c.CatchStatement.AsClause?.Type.ToString());
                    w.Str("name", c.CatchStatement.IdentifierName?.Identifier.ValueText);
                    Body("body", c.Statements, c);
                    j.WriteEndObject();
                }
                j.WriteEndArray();
                Body("finally", tb.FinallyBlock?.Statements ?? default, tb);
                w.End();
                break;
            case UsingBlockSyntax ub:
                w.Begin("using", line);
                j.WriteStartArray("resource");
                if (ub.UsingStatement.Expression is { } res) ExprStmt(res, Line(res));
                else Locals(ub.UsingStatement.Variables);
                j.WriteEndArray();
                Body("body", ub.Statements, ub);
                w.End();
                break;
            case WithBlockSyntax wb:
                w.Begin("with", line);
                ExprProp("target", wb.WithStatement.Expression);
                Body("body", wb.Statements, wb);
                w.End();
                break;
            case SelectBlockSyntax sb:
                // One flat "if" per Case (cond = the Select expression), as for C# switch.
                foreach (var cb in sb.CaseBlocks)
                {
                    w.Begin("if", Line(cb));
                    ExprProp("cond", sb.SelectStatement.Expression);
                    Body("then", cb.Statements, cb);
                    j.WriteStartArray("else");
                    j.WriteEndArray();
                    w.End();
                }
                break;
            case SyncLockBlockSyntax sl:
                Seq(sl.Statements);
                break;
            default:
                w.Text("other", line, s.ToString());
                break;
        }
    }

    /// <summary>If / ElseIf / Else: ElseIf blocks nest into the "else" list.</summary>
    void IfChain(int line, ExpressionSyntax cond, SyntaxList<StatementSyntax> then, SyntaxNode node,
        SyntaxList<ElseIfBlockSyntax> elseIfs, int idx, ElseBlockSyntax? elseBlock)
    {
        w.Begin("if", line);
        ExprProp("cond", cond);
        Body("then", then, node);
        w.J.WriteStartArray("else");
        if (idx < elseIfs.Count)
        {
            var e = elseIfs[idx];
            // Fallback text spans this ElseIf through the last arm / Else block,
            // so a capped chain never drops the arms after it.
            SyntaxNode last = elseBlock is not null ? elseBlock : elseIfs[elseIfs.Count - 1];
            Nested(() => IfChain(Line(e), e.ElseIfStatement.Condition, e.Statements, e, elseIfs, idx + 1, elseBlock),
                Line(e), () => text.ToString(TextSpan.FromBounds(e.SpanStart, last.Span.End)));
        }
        else if (elseBlock is not null && elseBlock.Statements.Count > 0)
        {
            Nested(() => Seq(elseBlock.Statements), elseBlock);
        }
        w.J.WriteEndArray();
        w.End();
    }

    void ControlVariable(VisualBasicSyntaxNode v)
    {
        switch (v)
        {
            case ExpressionSyntax e: Expr(e); break;
            case VariableDeclaratorSyntax d when d.Names.Count > 0:
                w.Name(d.Names[0].Identifier.ValueText, Line(d));
                break;
            default: w.Text("unknown", Line(v), v.ToString()); break;
        }
    }

    void Locals(SeparatedSyntaxList<VariableDeclaratorSyntax> declarators)
    {
        foreach (var d in declarators)
        {
            foreach (var n in d.Names)
            {
                w.Begin("local", Line(n));
                w.Str("name", n.Identifier.ValueText);
                w.Str("type", AsType(d.AsClause));
                ExprProp("init", DeclInit(d));
                w.OptStr("type_full", sem?.LocalType(n));
                w.End();
            }
        }
    }

    void AssignStmt(AssignmentStatementSyntax a, int line)
    {
        w.Begin("assign", line);
        ExprProp("target", a.Left);
        string? op = a.IsKind(SyntaxKind.SimpleAssignmentStatement) || a.IsKind(SyntaxKind.MidAssignmentStatement) ? "="
            : a.IsKind(SyntaxKind.AddAssignmentStatement) ? "+="
            : a.IsKind(SyntaxKind.SubtractAssignmentStatement) ? "-="
            : a.IsKind(SyntaxKind.ConcatenateAssignmentStatement) ? "concat="
            : null;
        if (op is not null)
        {
            w.Str("op", op);
            ExprProp("value", a.Right);
        }
        else
        {
            // x *= y  ->  x = (x * y), keeping "op" in the schema's closed set.
            w.Str("op", "=");
            w.J.WritePropertyName("value");
            w.Begin("bin", line);
            w.Str("op", a.OperatorToken.Text.TrimEnd('='));
            ExprProp("l", a.Left);
            ExprProp("r", a.Right);
            w.End();
        }
        w.End();
    }

    void ExprStmt(ExpressionSyntax e, int line)
    {
        w.Begin("expr", line);
        ExprProp("expr", e);
        w.End();
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
            case ParenthesizedExpressionSyntax p: ExprCore(p.Expression); break;
            case AwaitExpressionSyntax aw: ExprCore(aw.Expression); break;

            case LiteralExpressionSyntax lit:
                Literal(lit, line);
                break;
            case UnaryExpressionSyntax neg when neg.IsKind(SyntaxKind.UnaryMinusExpression)
                                               && neg.Operand is LiteralExpressionSyntax num
                                               && num.IsKind(SyntaxKind.NumericLiteralExpression):
                w.Lit(CSharpLowering.Negate(num.Token.Value), "number", line);
                break;

            case UnaryExpressionSyntax un when un.Kind() is SyntaxKind.NotExpression or SyntaxKind.UnaryMinusExpression:
                w.Begin("unary", line);
                w.Str("op", un.IsKind(SyntaxKind.NotExpression) ? "Not" : "-");
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
            case MeExpressionSyntax: w.Name("this", line); break;
            case MyClassExpressionSyntax: w.Name("this", line); break;
            case MyBaseExpressionSyntax: w.Name("base", line); break;
            case QualifiedNameSyntax q:
                Member(q.Left, q.Right.Identifier.ValueText, line, q);
                break;
            case MemberAccessExpressionSyntax ma when ma.IsKind(SyntaxKind.SimpleMemberAccessExpression):
                // Expression is null for ".Prop" inside a With block, and for
                // the bound member of "x?.Prop" (resolved through bindings).
                Member(ma.Expression ?? Bound(ma), ma.Name.Identifier.ValueText, line, ma);
                break;

            case ConditionalAccessExpressionSyntax ca:
                // Lowered like C#: x?.Y is member{x, Y}; the null check is dropped.
                if (ca.Expression is not null) bindings[LeftmostBinding(ca.WhenNotNull)] = ca.Expression;
                ExprCore(ca.WhenNotNull);
                break;

            case InvocationExpressionSyntax inv:
                w.Begin("call", line);
                ExprProp("fn", inv.Expression ?? Bound(inv)); // x?(0) binds fn to x
                Args(inv.ArgumentList?.Arguments ?? default);
                w.OptStr("sym", sem?.MemberSym(inv));
                w.End();
                break;

            case ObjectCreationExpressionSyntax oc:
                w.Begin("new", line);
                w.Str("type", oc.Type.ToString());
                j.WriteStartArray("args");
                foreach (var a in oc.ArgumentList?.Arguments ?? default) ArgValue(a);
                j.WriteEndArray();
                j.WriteStartArray("init");
                if (oc.Initializer is ObjectMemberInitializerSyntax omi) MemberInits(omi);
                else if (oc.Initializer is ObjectCollectionInitializerSyntax oci)
                    foreach (var x in oci.Initializer.Initializers) InitEntry(null, x);
                j.WriteEndArray();
                w.OptStr("type_full", sem?.ExprType(oc));
                w.End();
                break;
            case AnonymousObjectCreationExpressionSyntax an:
                w.Begin("new", line);
                w.Str("type", null);
                j.WriteStartArray("args");
                j.WriteEndArray();
                j.WriteStartArray("init");
                MemberInits(an.Initializer);
                j.WriteEndArray();
                w.End();
                break;
            case ArrayCreationExpressionSyntax ac:
                w.Begin("new", line);
                w.Str("type", ac.Type.ToString() + string.Concat(ac.RankSpecifiers.Select(r => r.ToString())));
                j.WriteStartArray("args");
                j.WriteEndArray();
                j.WriteStartArray("init");
                foreach (var x in ac.Initializer.Initializers) InitEntry(null, x);
                j.WriteEndArray();
                w.OptStr("type_full", sem?.ExprType(ac));
                w.End();
                break;
            case CollectionInitializerSyntax ci:
                w.Begin("new", line);
                w.Str("type", null);
                j.WriteStartArray("args");
                j.WriteEndArray();
                j.WriteStartArray("init");
                foreach (var x in ci.Initializers) InitEntry(null, x);
                j.WriteEndArray();
                w.End();
                break;

            case BinaryExpressionSyntax b:
                w.Begin("bin", line);
                w.Str("op", b.IsKind(SyntaxKind.ConcatenateExpression) ? "concat" : b.OperatorToken.Text);
                ExprProp("l", b.Left);
                ExprProp("r", b.Right);
                w.End();
                break;
            case BinaryConditionalExpressionSyntax bc: // If(a, b)
                w.Begin("bin", line);
                w.Str("op", "??");
                ExprProp("l", bc.FirstExpression);
                ExprProp("r", bc.SecondExpression);
                w.End();
                break;
            case TernaryConditionalExpressionSyntax tc: // If(c, t, f)
                w.Begin("cond", line);
                ExprProp("c", tc.Condition);
                ExprProp("t", tc.WhenTrue);
                ExprProp("f", tc.WhenFalse);
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

            case CastExpressionSyntax cast: // CType / DirectCast / TryCast
                Cast(cast.Type.ToString(), cast.Expression, line);
                break;
            case PredefinedCastExpressionSyntax pc:
                Cast(PredefinedCasts.TryGetValue(pc.Keyword.ValueText, out var t) ? t : pc.Keyword.ValueText,
                    pc.Expression, line);
                break;

            case SingleLineLambdaExpressionSyntax sl:
                w.Begin("lambda", line);
                LambdaParams(sl.SubOrFunctionHeader.ParameterList);
                j.WritePropertyName("body");
                if (sl.Body is ExpressionSyntax body) Expr(body);
                else
                {
                    j.WriteStartArray();
                    if (sl.Body is StatementSyntax st) Nested(() => Stmt(st), sl);
                    j.WriteEndArray();
                }
                w.End();
                break;
            case MultiLineLambdaExpressionSyntax ml:
                w.Begin("lambda", line);
                LambdaParams(ml.SubOrFunctionHeader.ParameterList);
                Body("body", ml.Statements, ml);
                w.End();
                break;

            case UnaryExpressionSyntax ao when ao.IsKind(SyntaxKind.AddressOfExpression):
                // `AddressOf Handler` is a method-group reference: lowered as the operand name / member.
                ExprCore(ao.Operand);
                break;

            default:
                w.Text("unknown", line, e.ToString());
                break;
        }
    }

    ExpressionSyntax? Bound(SyntaxNode n) => bindings.TryGetValue(n, out var recv) ? recv : null;

    /// <summary>Follows the left spine of a ?. WhenNotNull chain down to the
    /// receiver-less node that binds to the ConditionalAccess receiver.</summary>
    static SyntaxNode LeftmostBinding(ExpressionSyntax n)
    {
        while (true)
        {
            switch (n)
            {
                case MemberAccessExpressionSyntax { Expression: { } inner }: n = inner; continue;
                case InvocationExpressionSyntax { Expression: { } inner }: n = inner; continue;
                case ConditionalAccessExpressionSyntax { Expression: { } inner }: n = inner; continue;
            }
            return n;
        }
    }

    /// <summary>member node; symNode is the access the symbol binds to.</summary>
    void Member(ExpressionSyntax? obj, string name, int line, ExpressionSyntax symNode)
    {
        w.Begin("member", line);
        ExprProp("obj", obj);
        w.Str("name", name);
        w.OptStr("sym", sem?.MemberSym(symNode));
        w.End();
    }

    void Cast(string type, ExpressionSyntax e, int line)
    {
        w.Begin("cast", line);
        w.Str("type", type);
        ExprProp("e", e);
        w.End();
    }

    /// <summary>Positional args to "args", Name:=value args to "named".</summary>
    void Args(SeparatedSyntaxList<ArgumentSyntax> args)
    {
        var j = w.J;
        j.WriteStartArray("args");
        foreach (var a in args)
            if (a is not SimpleArgumentSyntax { NameColonEquals: not null }) ArgValue(a);
        j.WriteEndArray();
        j.WriteStartObject("named");
        foreach (var a in args)
        {
            if (a is SimpleArgumentSyntax { NameColonEquals: { } nce } named)
            {
                j.WritePropertyName(IrWriter.Clean(nce.Name.Identifier.ValueText));
                Expr(named.Expression);
            }
        }
        j.WriteEndObject();
    }

    void ArgValue(ArgumentSyntax a)
    {
        if (a is SimpleArgumentSyntax sa) Expr(sa.Expression);
        else w.Text("unknown", Line(a), a.ToString()); // omitted or range argument
    }

    void MemberInits(ObjectMemberInitializerSyntax init)
    {
        foreach (var f in init.Initializers)
        {
            switch (f)
            {
                case NamedFieldInitializerSyntax nf:
                    InitEntry(nf.Name.Identifier.ValueText, nf.Expression);
                    break;
                case InferredFieldInitializerSyntax inf:
                    InitEntry(inf.Expression switch
                    {
                        IdentifierNameSyntax i => i.Identifier.ValueText,
                        MemberAccessExpressionSyntax m => m.Name.Identifier.ValueText,
                        _ => null,
                    }, inf.Expression);
                    break;
            }
        }
    }

    void InitEntry(string? name, ExpressionSyntax value)
    {
        w.J.WriteStartObject();
        w.Str("name", name);
        ExprProp("value", value);
        w.J.WriteEndObject();
    }

    void Literal(LiteralExpressionSyntax lit, int line)
    {
        if (lit.IsKind(SyntaxKind.StringLiteralExpression))
            w.Lit(lit.Token.ValueText, "string", line);
        else if (lit.IsKind(SyntaxKind.CharacterLiteralExpression))
            w.Lit(lit.Token.Value, "char", line);
        else if (lit.IsKind(SyntaxKind.NumericLiteralExpression))
            w.Lit(lit.Token.Value, "number", line);
        else if (lit.IsKind(SyntaxKind.TrueLiteralExpression))
            w.Lit(true, "bool", line);
        else if (lit.IsKind(SyntaxKind.FalseLiteralExpression))
            w.Lit(false, "bool", line);
        else if (lit.IsKind(SyntaxKind.NothingLiteralExpression))
            w.Lit(null, "null", line);
        else
            w.Text("unknown", line, lit.ToString()); // date literals
    }

    // -- type discovery -------------------------------------------------------

    sealed class TypeCollector : VisualBasicSyntaxWalker
    {
        public readonly List<(DeclarationStatementSyntax Node, string Namespace, string Name)> Found = [];
        readonly List<string> ns = [];
        readonly List<string> outer = [];

        public override void VisitNamespaceBlock(NamespaceBlockSyntax node)
        {
            ns.Add(node.NamespaceStatement.Name.ToString());
            base.VisitNamespaceBlock(node);
            ns.RemoveAt(ns.Count - 1);
        }

        public override void VisitClassBlock(ClassBlockSyntax node) =>
            Add(node, node.BlockStatement.Identifier.ValueText, () => base.VisitClassBlock(node));

        public override void VisitStructureBlock(StructureBlockSyntax node) =>
            Add(node, node.BlockStatement.Identifier.ValueText, () => base.VisitStructureBlock(node));

        public override void VisitInterfaceBlock(InterfaceBlockSyntax node) =>
            Add(node, node.BlockStatement.Identifier.ValueText, () => base.VisitInterfaceBlock(node));

        public override void VisitModuleBlock(ModuleBlockSyntax node) =>
            Add(node, node.BlockStatement.Identifier.ValueText, () => base.VisitModuleBlock(node));

        public override void VisitEnumBlock(EnumBlockSyntax node) =>
            Add(node, node.EnumStatement.Identifier.ValueText, () => { });

        // Member bodies never declare types: skip them.
        public override void VisitMethodBlock(MethodBlockSyntax node) { }
        public override void VisitConstructorBlock(ConstructorBlockSyntax node) { }
        public override void VisitPropertyBlock(PropertyBlockSyntax node) { }
        public override void VisitOperatorBlock(OperatorBlockSyntax node) { }
        public override void VisitEventBlock(EventBlockSyntax node) { }
        public override void VisitFieldDeclaration(FieldDeclarationSyntax node) { }

        void Add(DeclarationStatementSyntax node, string id, Action descend)
        {
            Found.Add((node, string.Join(".", ns), string.Join(".", outer.Append(id))));
            outer.Add(id);
            descend();
            outer.RemoveAt(outer.Count - 1);
        }
    }
}
