using System.Text;
using System.Text.Json;
using Microsoft.CodeAnalysis;

namespace RoslynIr;

/// <summary>
/// roslyn-ir CLI (IR schema 2).
///   roslyn-ir probe                     -> {"ok": true, "schema": 2}
///   roslyn-ir parse --input req.json    -> one FileIR JSON object per line on stdout
/// Per-project request keys: refs ("net48" default | "netcore"), global_usings
/// (C# namespaces), imports (VB global imports); "references" is ignored.
/// stdout carries only JSON Lines; diagnostics go to stderr.
/// </summary>
internal static class Program
{
    // Exit codes: 0 ok, 1 fatal (unreadable request, probe failure), 2 usage.
    const int ExitFatal = 1;
    const int ExitUsage = 2;

    static int Main(string[] args)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        // Roslyn and the lowerers recurse over the tree; run on a thread with a
        // generous stack so pathological nesting degrades instead of crashing.
        int rc = ExitFatal;
        var worker = new Thread(() => rc = Run(args), 64 * 1024 * 1024);
        worker.Start();
        worker.Join();
        return rc;
    }

    static int Run(string[] args)
    {
        try
        {
            if (args.Length == 1 && args[0] == "probe") return Probe();
            if (args.Length == 3 && args[0] == "parse" && args[1] == "--input") return Parse(args[2]);
            Console.Error.WriteLine("usage: roslyn-ir probe | roslyn-ir parse --input <request.json>");
            return ExitUsage;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"roslyn-ir: fatal: {ex.GetType().Name}: {ex.Message}");
            return ExitFatal;
        }
    }

    /// <summary>Parses and lowers one embedded snippet per language; any exception is fatal.</summary>
    static int Probe()
    {
        const string cs =
            "namespace P { [Authorize] public class C : Controller {\n" +
            "  public ActionResult A(int id) { var s = \"x\" + id; return View(); } } }\n";
        const string vb =
            "Public Class C\n  Inherits Page\n" +
            "  Protected Sub A(sender As Object, e As EventArgs) Handles b.Click\n" +
            "    Dim s As String = \"a\" & Request(\"q\")\n  End Sub\nEnd Class\n";

        // A publish without refs/net48 would still "work" but resolve no
        // symbols, silently weakening every rule; make it loud instead.
        foreach (var prof in new[] { "net48", "netcore" })
            if (Semantics.RefCount(prof) == 0)
            {
                Console.Error.WriteLine("roslyn-ir: probe failed: no reference assemblies loaded from "
                    + Path.Combine(AppContext.BaseDirectory, "refs", prof)
                    + "; republish the helper (dotnet publish tools/roslyn-ir/src/RoslynIr.csproj -c Release -o tools/roslyn-ir/bin)");
                return ExitFatal;
            }

        const string csCore =
            "using Microsoft.AspNetCore.Mvc; [ApiController] public class C : ControllerBase " +
            "{ public IActionResult A() => Ok(); }\n";

        // Exercises the full semantic path (reference loading, compilation,
        // annotation) on the snippets; no target files are involved.
        foreach (var (lang, src, prof) in new[] { ("cs", cs, "net48"), ("vb", vb, "net48"), ("cs", csCore, "netcore") })
        {
            var tree = ParseTree(lang, src, "probe");
            var compilation = Semantics.Compile(lang, "probe", [tree], null, prof);
            var bytes = LowerToBytes(lang, "probe", "probe", tree, Semantics.For(compilation, tree));
            using var doc = JsonDocument.Parse(bytes);
            if (doc.RootElement.GetProperty("types").GetArrayLength() != 1)
                throw new InvalidOperationException($"probe: {lang} snippet lowered to an unexpected shape");
            // A half-populated refs/netcore would compile but resolve nothing: require the symbol.
            if (prof == "netcore" && !Encoding.UTF8.GetString(bytes).Contains("\"Microsoft.AspNetCore.Mvc.ControllerBase.Ok\""))
                throw new InvalidOperationException("probe: netcore snippet did not resolve Microsoft.AspNetCore.Mvc.ControllerBase.Ok; "
                    + "refs/netcore looks incomplete, republish the helper");
        }

        using var stdout = Console.OpenStandardOutput();
        stdout.Write(Encoding.UTF8.GetBytes($"{{\"ok\":true,\"schema\":{IrWriter.Schema}}}\n"));
        return 0;
    }

    static int Parse(string requestPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllBytes(requestPath));
        var req = doc.RootElement;
        string root = Path.GetFullPath(req.GetProperty("root").GetString()
                                       ?? throw new InvalidDataException("request.root is null"));

        using var stdout = new BufferedStream(Console.OpenStandardOutput(), 1 << 16);
        foreach (var project in req.GetProperty("projects").EnumerateArray())
        {
            string name = project.GetProperty("name").GetString() ?? "";
            string language = project.GetProperty("language").GetString() ?? "";
            // "references" (project-to-project) is accepted but ignored: the
            // compilation sees only this project's files plus the selected refs profile
            // (refs/net48 or refs/netcore).

            // Optional extra VB global imports, added to the template defaults.
            var imports = new List<string>();
            if (project.TryGetProperty("imports", out var imps) && imps.ValueKind == JsonValueKind.Array)
                foreach (var i in imps.EnumerateArray())
                    if (i.GetString() is { Length: > 0 } ns) imports.Add(ns);

            // Optional reference profile ("net48" default, or "netcore") and
            // C# global usings (namespaces) for SDK-style implicit usings.
            string profile = project.TryGetProperty("refs", out var rf) && rf.ValueKind == JsonValueKind.String
                ? rf.GetString() ?? "net48" : "net48";
            var usings = new List<string>();
            if (project.TryGetProperty("global_usings", out var gus) && gus.ValueKind == JsonValueKind.Array)
                foreach (var g in gus.EnumerateArray())
                    if (g.GetString() is { Length: > 0 } gns) usings.Add(gns);

            // Optional C# preprocessor symbols (the target framework's, plus DefineConstants).
            var defines = new List<string>();
            if (project.TryGetProperty("defines", out var defs) && defs.ValueKind == JsonValueKind.Array)
                foreach (var d in defs.EnumerateArray())
                    if (d.GetString() is { Length: > 0 } dn) defines.Add(dn);

            // Pass 1: read and parse every file; a failure costs only that file.
            var files = new List<(string Rel, SyntaxTree? Tree, string? Error)>();
            foreach (var f in project.GetProperty("files").EnumerateArray())
            {
                string file = f.GetString() ?? "";
                string rel = Relative(root, file);
                try
                {
                    string source = SourceDecoder.Decode(File.ReadAllBytes(Path.Combine(root, file)));
                    files.Add((rel, ParseTree(language, source, rel, defines), null));
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"roslyn-ir: {rel}: {ex.GetType().Name}: {ex.Message}");
                    files.Add((rel, null, ex.Message));
                }
            }

            // One compilation per project, one SemanticModel per tree.
            var trees = files.Where(x => x.Tree is not null).Select(x => x.Tree!).ToList();
            var compilation = trees.Count > 0 ? Semantics.Compile(language, name, trees, imports, profile, usings) : null;

            // Pass 2: lower in request order.
            foreach (var (rel, tree, error) in files)
            {
                byte[] line = tree is null ? ErrorRecord(rel, error ?? "unreadable") : LowerFile(language, rel, name, tree, compilation);
                stdout.Write(line);
                stdout.WriteByte((byte)'\n');
            }
        }
        stdout.Flush();
        return 0;
    }

    /// <summary>Lowers one file with semantic annotation; if that throws,
    /// retries syntax-only, and only then gives up on the file.</summary>
    static byte[] LowerFile(string language, string rel, string project, SyntaxTree tree, Compilation? compilation)
    {
        try
        {
            return LowerToBytes(language, rel, project, tree, Semantics.For(compilation, tree));
        }
        catch (Exception ex) when (compilation is not null)
        {
            Console.Error.WriteLine($"roslyn-ir: {rel}: semantic lowering failed, retrying syntax only: {ex.GetType().Name}: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"roslyn-ir: {rel}: {ex.GetType().Name}: {ex.Message}");
            return ErrorRecord(rel, ex.Message);
        }
        try
        {
            return LowerToBytes(language, rel, project, tree, null);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"roslyn-ir: {rel}: {ex.GetType().Name}: {ex.Message}");
            return ErrorRecord(rel, ex.Message);
        }
    }

    static SyntaxTree ParseTree(string language, string source, string path, IReadOnlyList<string>? defines = null) => language switch
    {
        "cs" => CSharpLowering.Parse(source, path, defines),
        "vb" => VbLowering.Parse(source, path),
        _ => throw new NotSupportedException($"unsupported language '{language}' (expected cs or vb)"),
    };

    /// <summary>Lowers a whole file into a private buffer, so a mid-file
    /// failure never leaves a partial line on stdout.</summary>
    static byte[] LowerToBytes(string language, string rel, string project, SyntaxTree tree, Semantics? sem)
    {
        var ms = new MemoryStream();
        using (var json = new Utf8JsonWriter(ms, IrWriter.Options))
        {
            var w = new IrWriter(json);
            switch (language)
            {
                case "cs": CSharpLowering.WriteFile(w, rel, project, tree, sem); break;
                case "vb": VbLowering.WriteFile(w, rel, project, tree, sem); break;
                default: throw new NotSupportedException($"unsupported language '{language}' (expected cs or vb)");
            }
        }
        return ms.ToArray();
    }

    static byte[] ErrorRecord(string rel, string message)
    {
        var ms = new MemoryStream();
        using (var json = new Utf8JsonWriter(ms, IrWriter.Options))
        {
            json.WriteStartObject();
            json.WriteString("path", IrWriter.Clean(rel));
            json.WriteString("error", IrWriter.Clean(message));
            json.WriteEndObject();
        }
        return ms.ToArray();
    }

    /// <summary>Path relative to root with forward slashes.</summary>
    static string Relative(string root, string file)
    {
        try
        {
            string rel = Path.GetRelativePath(root, Path.GetFullPath(Path.Combine(root, file)));
            return Path.DirectorySeparatorChar == '/' ? rel : rel.Replace(Path.DirectorySeparatorChar, '/');
        }
        catch (Exception)
        {
            return file.Replace('\\', '/');
        }
    }
}

/// <summary>
/// Source decoding shared with the Python side: UTF-8 (BOM stripped), falling
/// back to Windows-1252 when the bytes are not valid UTF-8. UTF-16 files are
/// honored when they carry a BOM. Decoding never changes the line structure,
/// so IR line numbers match the original file.
/// </summary>
internal static class SourceDecoder
{
    static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static string Decode(byte[] bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);

        int start = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
        try
        {
            return StrictUtf8.GetString(bytes, start, bytes.Length - start);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.GetEncoding(1252).GetString(bytes, start, bytes.Length - start);
        }
    }
}
