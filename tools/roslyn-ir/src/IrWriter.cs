using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace RoslynIr;

/// <summary>
/// Shared JSON emitter for both lowerers. Wraps a Utf8JsonWriter with the
/// handful of shapes the schema-1 IR uses (Expr/Stmt objects carry "k" and
/// "line"), and owns the language-neutral normalizations (modifiers,
/// attribute names) so C# and VB produce identical IR for identical intent.
/// </summary>
internal sealed class IrWriter
{
    public const int Schema = 1;

    // Relaxed escaping keeps non-ASCII text readable; quotes and control
    // characters are still escaped, so each record stays a single line.
    public static readonly JsonWriterOptions Options = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// JSON nesting budget. Lowerers check the writer's real depth before
    /// opening a nested Stmt list or Expr; past the budget the remaining
    /// syntax is emitted as other/unknown text. A check sits at least every
    /// 4 JSON levels (try -> catches -> catch -> body is the widest step), so
    /// output stays within MaxDepth + 5: far below Utf8JsonWriter's 1000 and
    /// Python json's ~1000-frame recursion limit, with headroom for recursive
    /// Python walkers over the IR.
    /// </summary>
    public const int MaxDepth = 400;

    public Utf8JsonWriter J { get; }

    public IrWriter(Utf8JsonWriter j) => J = j;

    public bool AtDepthCap => J.CurrentDepth >= MaxDepth;

    // -- primitives -----------------------------------------------------

    public void Str(string name, string? value)
    {
        if (value is null) J.WriteNull(name);
        else J.WriteString(name, Clean(value));
    }

    /// <summary>Optional key: written only when the value is known (the
    /// semantic keys are additive and omitted when unresolved).</summary>
    public void OptStr(string name, string? value)
    {
        if (value is not null) J.WriteString(name, Clean(value));
    }

    public void StrValue(string? value)
    {
        if (value is null) J.WriteNullValue();
        else J.WriteStringValue(Clean(value));
    }

    public void StrArray(string name, IEnumerable<string> values)
    {
        J.WriteStartArray(name);
        foreach (var v in values) StrValue(v);
        J.WriteEndArray();
    }

    /// <summary>Opens an Expr/Stmt object: {"k": kind, "line": n, ...}.</summary>
    public void Begin(string k, int line)
    {
        J.WriteStartObject();
        J.WriteString("k", k);
        J.WriteNumber("line", line);
    }

    public void End() => J.WriteEndObject();

    /// <summary>Fallback node for unmapped syntax: other (Stmt) / unknown (Expr).</summary>
    public void Text(string k, int line, string text)
    {
        Begin(k, line);
        Str("text", text);
        End();
    }

    public void Name(string id, int line)
    {
        Begin("name", line);
        Str("id", id);
        End();
    }

    /// <summary>lit node; value is a boxed literal value from Roslyn.</summary>
    public void Lit(object? value, string t, int line)
    {
        Begin("lit", line);
        J.WritePropertyName("v");
        switch (value)
        {
            case null: J.WriteNullValue(); break;
            case bool b: J.WriteBooleanValue(b); break;
            case string s: StrValue(s); break;
            case char c: StrValue(c.ToString()); break;
            case int i: J.WriteNumberValue(i); break;
            case uint ui: J.WriteNumberValue(ui); break;
            case long l: J.WriteNumberValue(l); break;
            case ulong ul: J.WriteNumberValue(ul); break;
            case decimal m: J.WriteNumberValue(m); break;
            case float f when float.IsFinite(f): J.WriteNumberValue(f); break;
            case double d when double.IsFinite(d): J.WriteNumberValue(d); break;
            default: StrValue(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture)); break;
        }
        Str("t", t);
        End();
    }

    // -- file records ---------------------------------------------------

    public void BeginFile(string path, string language, string project, int parseErrors)
    {
        J.WriteStartObject();
        Str("path", path);
        Str("language", language);
        Str("project", project);
        J.WriteNumber("parse_errors", parseErrors);
        J.WriteStartArray("types");
    }

    public void EndFile()
    {
        J.WriteEndArray();
        J.WriteEndObject();
    }

    // -- shared normalization ------------------------------------------

    static readonly Dictionary<string, string> VbModifierMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Shared"] = "static",
        ["Overrides"] = "override",
        ["Overridable"] = "virtual",
        ["MustOverride"] = "abstract",
        ["MustInherit"] = "abstract",
        ["NotInheritable"] = "sealed",
        ["NotOverridable"] = "sealed",
        ["Friend"] = "internal",
        ["Shadows"] = "new",
    };

    /// <summary>
    /// Lowercases modifiers, maps VB keywords to their C# spelling, and merges
    /// the two-word accessibilities into one entry ("protected internal",
    /// "private protected") for both languages.
    /// </summary>
    public static List<string> NormalizeModifiers(IEnumerable<string> raw, bool vb)
    {
        var mods = raw
            .Select(m => vb && VbModifierMap.TryGetValue(m, out var mapped) ? mapped : m.ToLowerInvariant())
            .ToList();
        MergePair(mods, "protected", "internal", "protected internal");
        MergePair(mods, "private", "protected", "private protected");
        return mods;
    }

    static void MergePair(List<string> mods, string a, string b, string merged)
    {
        int ia = mods.IndexOf(a), ib = mods.IndexOf(b);
        if (ia < 0 || ib < 0) return;
        int first = Math.Min(ia, ib), second = Math.Max(ia, ib);
        mods.RemoveAt(second);
        mods[first] = merged;
    }

    /// <summary>"System.Web.Mvc.AuthorizeAttribute" -> "Authorize" (qualifier already stripped by caller).</summary>
    public static string StripAttributeSuffix(string name) =>
        name.Length > "Attribute".Length && name.EndsWith("Attribute", StringComparison.Ordinal)
            ? name[..^"Attribute".Length]
            : name;

    /// <summary>Replaces lone UTF-16 surrogates (legal in C#/VB literals, illegal in JSON) with U+FFFD.</summary>
    public static string Clean(string s)
    {
        int i = 0;
        for (; i < s.Length; i++)
            if (char.IsSurrogate(s[i])) break;
        if (i == s.Length) return s;

        var sb = new StringBuilder(s.Length);
        sb.Append(s, 0, i);
        for (; i < s.Length; i++)
        {
            char c = s[i];
            if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
            {
                sb.Append(c).Append(s[++i]);
            }
            else if (char.IsSurrogate(c))
            {
                sb.Append('�');
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }
}
