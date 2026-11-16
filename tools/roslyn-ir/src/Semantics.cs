using Microsoft.CodeAnalysis;
using CS = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace RoslynIr;

/// <summary>
/// Best-effort semantic annotation shared by both lowerers. Each project is
/// compiled once (its own files plus the .NET Framework 4.8 reference
/// assemblies shipped in refs/net48 next to the binary); project-to-project
/// references are ignored -- cross-project resolution is the Python model's job.
///
/// Every query is wrapped: a semantic failure on one node yields null (the
/// key is omitted), never an exception that would cost the file. Unresolved
/// symbols are normal -- third-party assemblies are never available.
///
/// Names are built by hand rather than with ToDisplayString so C# and VB
/// produce the same spelling ("System.String[]", not VB's "String()"), and
/// generic arguments are dropped ("System.Collections.Generic.List").
/// </summary>
internal sealed class Semantics
{
    readonly SemanticModel model;

    Semantics(SemanticModel model) => this.model = model;

    public static Semantics? For(Compilation? compilation, SyntaxTree tree)
    {
        if (compilation is null) return null;
        try { return new Semantics(compilation.GetSemanticModel(tree)); }
        catch (Exception) { return null; }
    }

    // -- compilations ---------------------------------------------------------

    // One lazily loaded reference set per profile folder under refs/.
    static readonly Dictionary<string, Lazy<IReadOnlyList<MetadataReference>>> RefSets = new()
    {
        ["net48"] = new(() => LoadRefs("net48")),
        ["netcore"] = new(() => LoadRefs("netcore")),
    };

    /// <summary>Unknown profile names fall back to net48 with a warning.</summary>
    static string Normalize(string? profile)
    {
        if (profile is null) return "net48";
        if (RefSets.ContainsKey(profile)) return profile;
        Console.Error.WriteLine($"roslyn-ir: warning: unknown refs profile '{profile}'; using net48");
        return "net48";
    }

    static IReadOnlyList<MetadataReference> RefsFor(string profile) => RefSets[Normalize(profile)].Value;

    /// <summary>Number of reference assemblies that loaded for a profile; probe fails when zero.</summary>
    public static int RefCount(string profile) => RefsFor(profile).Count;

    /// <summary>All refs/&lt;profile&gt;/*.dll beside the binary, loaded once per process
    /// and shared by every project's compilation.</summary>
    static IReadOnlyList<MetadataReference> LoadRefs(string profile)
    {
        string dir = Path.Combine(AppContext.BaseDirectory, "refs", profile);
        var list = new List<MetadataReference>();
        if (!Directory.Exists(dir))
        {
            Console.Error.WriteLine($"roslyn-ir: warning: {dir} not found; symbols will not resolve");
            return list;
        }
        foreach (var dll in Directory.EnumerateFiles(dir, "*.dll").OrderBy(p => p, StringComparer.Ordinal))
        {
            try { list.Add(MetadataReference.CreateFromFile(dll)); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"roslyn-ir: warning: skipping reference {Path.GetFileName(dll)}: {ex.Message}");
            }
        }
        return list;
    }

    // Project-level imports every Visual Studio VB project template declares;
    // VB sources rely on them without an Imports line (the .vbproj is not
    // read here, so these are the defaults, not the project's exact list).
    static readonly string[] VbDefaultImports =
    [
        "Microsoft.VisualBasic", "System", "System.Collections", "System.Collections.Generic",
        "System.Data", "System.Diagnostics", "System.Linq", "System.Xml.Linq",
    ];

    /// <summary>One compilation for a project's parsed trees; null if it cannot be built.</summary>
    public static Compilation? Compile(string language, string project, IReadOnlyList<SyntaxTree> trees,
        IReadOnlyList<string>? extraImports = null, string profile = "net48",
        IReadOnlyList<string>? globalUsings = null)
    {
        try
        {
            string name = string.IsNullOrEmpty(project) ? "project" : project;
            var refs = RefsFor(profile);
            return language switch
            {
                "cs" => CS.CSharpCompilation.Create(name, WithGlobalUsings(trees, globalUsings), refs,
                    new CS.CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, allowUnsafe: true)),
                "vb" => VB.VisualBasicCompilation.Create(name, trees.Cast<VB.VisualBasicSyntaxTree>(), refs,
                    new VB.VisualBasicCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
                        globalImports: VbDefaultImports.Concat(extraImports ?? []).Distinct().Select(ParseImport).OfType<VB.GlobalImport>(),
                        optionStrict: VB.OptionStrict.Off, optionInfer: true)),
                _ => null,
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"roslyn-ir: {project}: compilation failed, emitting syntax only: {ex.Message}");
            return null;
        }
    }

    /// <summary>The project's trees plus, when namespaces are given, one extra tree
    /// declaring them as C# global usings (parsed with the same options).</summary>
    static IEnumerable<CS.CSharpSyntaxTree> WithGlobalUsings(IReadOnlyList<SyntaxTree> trees, IReadOnlyList<string>? globalUsings)
    {
        var all = trees.Cast<CS.CSharpSyntaxTree>().ToList();
        var ns = (globalUsings ?? []).Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).Distinct().ToList();
        if (ns.Count > 0 && all.Count > 0)
            all.Add((CS.CSharpSyntaxTree)CS.CSharpSyntaxTree.ParseText(
                string.Concat(ns.Select(n => $"global using global::{n};\n")),
                (CS.CSharpParseOptions)all[0].Options, "GlobalUsings.g.cs"));
        return all;
    }

    /// <summary>A malformed caller-supplied import is skipped, not fatal.</summary>
    static VB.GlobalImport? ParseImport(string ns)
    {
        try { return VB.GlobalImport.Parse(ns); }
        catch (Exception) { return null; }
    }

    // -- queries --------------------------------------------------------------

    /// <summary>"ContainingType.Member" for the method/property/field/event a
    /// call or member access binds to. Overload-resolution failures still
    /// count when every candidate names the same member.</summary>
    public string? MemberSym(SyntaxNode node)
    {
        try
        {
            var info = model.GetSymbolInfo(node);
            if (info.Symbol is not null) return MemberName(info.Symbol);
            string? agreed = null;
            foreach (var c in info.CandidateSymbols)
            {
                var n = MemberName(c);
                if (n is null || (agreed is not null && agreed != n)) return null;
                agreed = n;
            }
            return agreed;
        }
        catch (Exception) { return null; }
    }

    /// <summary>"ContainingType.member" for an identifier that binds to a field or
    /// property; locals, parameters, types and namespaces yield null.</summary>
    public string? NameSym(SyntaxNode node)
    {
        try
        {
            var sym = model.GetSymbolInfo(node).Symbol;
            if (sym is not (IFieldSymbol or IPropertySymbol)) return null;
            return MemberName(sym);
        }
        catch (Exception) { return null; }
    }

    /// <summary>"ContainingType.Item" when an element access binds to an indexer.</summary>
    public string? IndexSym(SyntaxNode node)
    {
        try
        {
            var info = model.GetSymbolInfo(node);
            var sym = info.Symbol ?? (info.CandidateSymbols.Length == 1 ? info.CandidateSymbols[0] : null);
            if (sym is not IPropertySymbol { IsIndexer: true } prop) return null;
            var owner = TypeName(prop.ContainingType);
            return owner is null ? null : owner + ".Item";
        }
        catch (Exception) { return null; }
    }

    /// <summary>Full name of an expression's type (e.g. the type a "new" creates).</summary>
    public string? ExprType(SyntaxNode node)
    {
        try { return TypeName(model.GetTypeInfo(node).Type); }
        catch (Exception) { return null; }
    }

    /// <summary>Full name of a declared local's (possibly inferred) type.</summary>
    public string? LocalType(SyntaxNode declarator)
    {
        try { return model.GetDeclaredSymbol(declarator) is ILocalSymbol l ? TypeName(l.Type) : null; }
        catch (Exception) { return null; }
    }

    // -- naming ---------------------------------------------------------------

    static string? MemberName(ISymbol s)
    {
        if (s is IMethodSymbol { ReducedFrom: { } unreduced }) s = unreduced; // extension method
        if (s is not (IMethodSymbol or IPropertySymbol or IFieldSymbol or IEventSymbol)) return null;
        var owner = TypeName(s.ContainingType);
        return owner is null ? null : owner + "." + s.Name;
    }

    public static string? TypeName(ITypeSymbol? t)
    {
        switch (t)
        {
            case null:
                return null;
            case IArrayTypeSymbol a:
                var elem = TypeName(a.ElementType);
                return elem is null ? null : elem + "[" + new string(',', a.Rank - 1) + "]";
            case IPointerTypeSymbol p:
                var pointee = TypeName(p.PointedAtType);
                return pointee is null ? null : pointee + "*";
            case INamedTypeSymbol n when n.TypeKind != TypeKind.Error && !n.IsAnonymousType && !n.IsTupleType:
                if (n.ContainingType is not null)
                {
                    var outer = TypeName(n.ContainingType);
                    return outer is null ? null : outer + "." + n.Name;
                }
                var ns = Namespace(n.ContainingNamespace);
                return ns.Length == 0 ? n.Name : ns + "." + n.Name;
            case ITypeParameterSymbol tp:
                return tp.Name;
            default:
                return null; // error, anonymous, tuple, dynamic, function pointer
        }
    }

    static string Namespace(INamespaceSymbol? ns)
    {
        var parts = new List<string>();
        for (; ns is not null && !ns.IsGlobalNamespace; ns = ns.ContainingNamespace)
            parts.Add(ns.Name);
        parts.Reverse();
        return string.Join(".", parts);
    }
}
