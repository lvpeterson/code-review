"""Data tables for the dotnet_legacy taint engine (sources, sinks, sanitizers,
guards, string helpers). Plain data only: the logic that reads them lives in
checks/dnl/taint.py, so adding a sink or sanitizer is a one-line change here.

Matching is symbol-first: the Roslyn helper stamps calls/members with
`sym` = containing type full name + "." + member, and that is authoritative
when present. Only when `sym` is absent (third-party types the helper could not
resolve, or a project that does not reference the assembly) does the engine fall
back to the receiver's declared simple type name, then to text patterns.
"""
from __future__ import annotations

from dataclasses import dataclass


# -- sources --------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    name: str
    sym: str            # regex over the full `sym` ("Type.Member")
    text: str | None    # regex over the receiver/member text when sym is absent


_REQ = r"System\.Web\.(HttpRequest|HttpRequestBase|HttpRequestWrapper)"
# `Request`, `this.Request`, `Page.Request`, `HttpContext.Current.Request`, optionally
# followed by one request collection. Used as a call/index receiver or as a member.
REQUEST_TEXT = (r"(?i)^((this|me)\.)?((httpcontext\.current|context|page)\.)?request"
                r"(\.(querystring|form|params|cookies|headers|servervariables|rawurl|url|files|unvalidated|path|pathinfo|"
                r"useragent|contenttype|apprelativecurrentexecutionfilepath|currentexecutionfilepath|filepath|inputstream))?$")

SOURCES: tuple[Source, ...] = (
    Source("Request", rf"^{_REQ}\.(QueryString|Form|Params|Cookies|Headers|ServerVariables|RawUrl|Url|"
                      r"UrlReferrer|Files|InputStream|Item|Unvalidated|Path|PathInfo|UserAgent|ContentType|"
                      r"AppRelativeCurrentExecutionFilePath|CurrentExecutionFilePath|FilePath)$", REQUEST_TEXT),
    Source("Request.Unvalidated", r"^System\.Web\.UnvalidatedRequestValues\.[A-Za-z]+$", None),
    Source("RouteData.Values", r"^System\.Web\.Routing\.RouteData\.Values$", r"(?i)(^|\.)routedata\.values$"),
    Source("TextBox.Text", r"^System\.Web\.UI\.WebControls\.TextBox\.Text$", None),
    Source("HiddenField.Value", r"^System\.Web\.UI\.WebControls\.HiddenField\.Value$", None),
    Source("ListControl.Selected", r"^System\.Web\.UI\.WebControls\.ListControl\.(SelectedValue|SelectedItem)$", None),
    Source("HtmlInputText.Value", r"^System\.Web\.UI\.HtmlControls\.HtmlInput(Text|Control|Hidden)\.Value$", None),
)

# Fallback for the WebForms rows above when `sym` is missing: a `.Text` / `.Value`
# / `.SelectedValue` member on a variable whose declared type is one of these.
FIELD_SOURCE_TYPES = r"(?i)^(TextBox|HiddenField|DropDownList|ListBox|RadioButtonList|HtmlInputText|HtmlInputHidden)$"
FIELD_SOURCE_MEMBERS = frozenset({"text", "value", "selectedvalue", "selecteditem"})

# Methods that read a value out of a tainted collection/object: the result keeps
# the receiver's taint (`Request.QueryString.Get("q")`). Other external calls on a
# tainted receiver do not propagate.
ACCESSOR_METHODS = frozenset({
    "get", "getvalues", "getkey", "getvalue", "toarray", "tolist", "first", "firstordefault",
    "single", "singleordefault", "elementat", "item", "getenumerator",
})


# -- sinks ----------------------------------------------------------------

@dataclass(frozen=True)
class Sink:
    kind: str
    name: str                        # table entry name reported in SinkHit.sink
    types: tuple[str, ...]           # full type names (sym match); last segment = simple name
    member: str                      # method / property name; ".ctor" for constructors
    args: tuple[int, ...] = (0,)     # checked argument indexes (calls and constructors)
    assign: bool = False             # the checked value is the right side of `x.Member = v`
    static_args: tuple[int, ...] | None = None   # indexes when called as `Type.Member(recv, ..)`
    recv_text: str | None = None     # receiver-text regex used when the receiver type is unknown
    derives: tuple[str, ...] = ()    # bare `Member(..)` inside a class deriving from one of these
    unresolved_ok: bool = False      # sym absent + member name alone is enough (dynamic LINQ)
    all_args: bool = False           # format-style call: every argument is checked, not just `args`


_DB = "System.Data."
_CMD = (_DB + "SqlClient.SqlCommand", _DB + "OleDb.OleDbCommand", _DB + "Odbc.OdbcCommand",
        _DB + "OracleClient.OracleCommand", "Oracle.ManagedDataAccess.Client.OracleCommand",
        "Oracle.DataAccess.Client.OracleCommand", _DB + "Common.DbCommand", _DB + "IDbCommand")
_ADAPTER = (_DB + "SqlClient.SqlDataAdapter", _DB + "OleDb.OleDbDataAdapter",
            _DB + "OracleClient.OracleDataAdapter", "Oracle.ManagedDataAccess.Client.OracleDataAdapter",
            "Oracle.DataAccess.Client.OracleDataAdapter")
_EF_DB = ("System.Data.Entity.Database",)
_EF_TEXT = r"(?i)(^|\.)database$"
_DYN = ("System.Linq.Dynamic.DynamicQueryable", "System.Linq.Dynamic.Core.DynamicQueryableExtensions",
        "System.Linq.Dynamic.Core.DynamicQueryable")
_RESP = ("System.Web.HttpResponse", "System.Web.HttpResponseBase", "System.Web.HttpResponseWrapper")
_RESP_TEXT = r"(?i)^((this|me)\.)?((httpcontext\.current|context|page)\.)?response$"
_CTRL = ("System.Web.Mvc.Controller", "System.Web.Mvc.ControllerBase")
_API = ("System.Web.Http.ApiController",)
_FILE = "System.IO.File"
_LOG = ("log4net.ILog",)
_WEBCLIENT = ("System.Net.WebClient",)
_HTTPCLIENT = ("System.Net.Http.HttpClient",)
# Formatters that rebuild arbitrary object graphs from their input. Json.NET TypeNameHandling is a
# configuration finding (rules_deser_xml), not a taint sink.
_FORMATTERS = ("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
               "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
               "System.Runtime.Serialization.NetDataContractSerializer",
               "System.Web.UI.LosFormatter", "System.Web.UI.ObjectStateFormatter")


def _each(kind: str, name: str, types, members: str, **kw) -> list[Sink]:
    """One Sink per `|`-separated member name."""
    return [Sink(kind, f"{name}.{m}", tuple(types), m, **kw) for m in members.split("|")]


SINKS: tuple[Sink, ...] = tuple(
    # sql
    _each("sql", "SqlCommand", _CMD, ".ctor", args=(0,))
    + _each("sql", "SqlCommand", _CMD, "CommandText", assign=True)
    + _each("sql", "SqlDataAdapter", _ADAPTER, ".ctor", args=(0,))
    + _each("sql", "Database", _EF_DB, "SqlQuery|ExecuteSqlCommand|ExecuteSqlCommandAsync", recv_text=_EF_TEXT)
    + _each("sql", "DbSet", ("System.Data.Entity.DbSet", "System.Data.Entity.IDbSet",
                              "System.Data.Entity.Infrastructure.DbSqlQuery"), "SqlQuery")
    # linq (dynamic LINQ takes the expression as a string)
    + _each("linq", "DynamicQueryable", _DYN, "Where|OrderBy|Select|GroupBy", args=(0,), static_args=(1,),
            unresolved_ok=True)
    # cmd
    + _each("cmd", "Process", ("System.Diagnostics.Process",), "Start", args=(0, 1))
    + _each("cmd", "ProcessStartInfo", ("System.Diagnostics.ProcessStartInfo",), ".ctor", args=(0, 1))
    + _each("cmd", "ProcessStartInfo", ("System.Diagnostics.ProcessStartInfo",), "FileName|Arguments", assign=True)
    # ldap
    + _each("ldap", "DirectorySearcher", ("System.DirectoryServices.DirectorySearcher",), "Filter", assign=True)
    + _each("ldap", "DirectorySearcher", ("System.DirectoryServices.DirectorySearcher",), ".ctor", args=(0, 1))
    + _each("ldap", "DirectoryEntry", ("System.DirectoryServices.DirectoryEntry",), ".ctor", args=(0,))
    # xpath
    + _each("xpath", "XmlNode", ("System.Xml.XmlNode", "System.Xml.XmlDocument", "System.Xml.XmlElement"),
            "SelectNodes|SelectSingleNode", args=(0,))
    + _each("xpath", "XPathNavigator", ("System.Xml.XPath.XPathNavigator",), "Select|Evaluate|SelectSingleNode",
            args=(0,))
    + _each("xpath", "XPathExpression", ("System.Xml.XPath.XPathExpression",), "Compile", args=(0,))
    # header
    + _each("header", "HttpResponse", _RESP, "AddHeader|AppendHeader", args=(1,), recv_text=_RESP_TEXT)
    + _each("header", "HttpCookie", ("System.Web.HttpCookie",), ".ctor", args=(1,))
    + _each("header", "HttpCookie", ("System.Web.HttpCookie",), "Value", assign=True)
    # xss
    + _each("xss", "HttpResponse", _RESP, "Write", args=(0,), recv_text=_RESP_TEXT)
    + _each("xss", "Literal", ("System.Web.UI.WebControls.Literal",), "Text", assign=True)
    + _each("xss", "Label", ("System.Web.UI.WebControls.Label",), "Text", assign=True)
    + _each("xss", "HtmlControl", ("System.Web.UI.HtmlControls.HtmlGenericControl",
                                    "System.Web.UI.HtmlControls.HtmlContainerControl"), "InnerHtml", assign=True)
    + _each("xss", "HtmlString", ("System.Web.HtmlString",), ".ctor", args=(0,))
    + _each("xss", "MvcHtmlString", ("System.Web.Mvc.MvcHtmlString",), "Create", args=(0,))
    + _each("xss", "HtmlHelper", ("System.Web.Mvc.HtmlHelper",), "Raw", args=(0,))
    + _each("xss", "Controller", _CTRL, "Content", args=(0,), derives=("Controller",))
    # path
    + _each("path", "File", (_FILE,), "ReadAllText|ReadAllBytes|ReadAllLines|WriteAllText|WriteAllBytes|"
                                      "AppendAllText|Open|OpenRead|OpenWrite|OpenText|Delete", args=(0,))
    + _each("path", "File", (_FILE,), "Copy|Move", args=(0, 1))
    + _each("path", "FileStream", ("System.IO.FileStream", "System.IO.StreamReader", "System.IO.StreamWriter",
                                    "System.IO.FileInfo"), ".ctor", args=(0,))
    + _each("path", "HttpServerUtility", ("System.Web.HttpServerUtility", "System.Web.HttpServerUtilityBase"),
            "MapPath", args=(0,))
    + _each("path", "HttpResponse", _RESP, "WriteFile|TransmitFile", args=(0,), recv_text=_RESP_TEXT)
    + _each("path", "Controller", _CTRL, "File", args=(0,), derives=("Controller",))
    + _each("path", "Directory", ("System.IO.Directory",), "GetFiles|Delete|CreateDirectory", args=(0,))
    # redirect
    + _each("redirect", "HttpResponse", _RESP, "Redirect|RedirectPermanent", args=(0,), recv_text=_RESP_TEXT)
    + _each("redirect", "Controller", _CTRL, "Redirect|RedirectPermanent", args=(0,), derives=("Controller",))
    + _each("redirect", "RedirectResult", ("System.Web.Mvc.RedirectResult",), ".ctor", args=(0,))
    + _each("redirect", "ApiController", _API, "Redirect", args=(0,), derives=("ApiController",))
    # ssrf
    + _each("ssrf", "WebClient", _WEBCLIENT, "DownloadString|DownloadData|DownloadFile|OpenRead|UploadString|"
                                             "UploadData|UploadValues", args=(0,))
    + _each("ssrf", "WebRequest", ("System.Net.WebRequest", "System.Net.HttpWebRequest"),
            "Create|CreateHttp", args=(0,))
    + _each("ssrf", "HttpClient", _HTTPCLIENT, "GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|"
                                                "PostAsync|PutAsync|DeleteAsync|SendAsync", args=(0,))
    + _each("ssrf", "RestClient", ("RestSharp.RestClient",), ".ctor", args=(0,))
    + _each("ssrf", "RestRequest", ("RestSharp.RestRequest",), ".ctor", args=(0,))
    + _each("ssrf", "RestClient", ("RestSharp.RestClient",), "BaseUrl", assign=True)
    # deser (dangerous formatters only)
    + _each("deser", "Formatter", _FORMATTERS, "Deserialize|ReadObject", args=(0,))
    # xxe: every XML entry point that takes content / a path / a stream. Whether the parser is
    # actually configured to resolve entities is decided in rules_deser_xml (a hit on a line it
    # does not list as insecure is dropped by rules_taint).
    + _each("xxe", "XmlDocument", ("System.Xml.XmlDocument",), "Load|LoadXml", args=(0,))
    + _each("xxe", "XmlTextReader", ("System.Xml.XmlTextReader",), ".ctor", args=(0,))
    + _each("xxe", "XmlReader", ("System.Xml.XmlReader",), "Create", args=(0,))
    + _each("xxe", "XPathDocument", ("System.Xml.XPath.XPathDocument",), ".ctor", args=(0,))
    + _each("xxe", "DataSet", ("System.Data.DataSet",), "ReadXml", args=(0,))
    + _each("xxe", "XDocument", ("System.Xml.Linq.XDocument", "System.Xml.Linq.XElement"), "Load", args=(0,))
    # log
    + _each("log", "ILog", _LOG, "Debug|Info|Warn|Error|Fatal", args=(0,))
    + _each("log", "ILog", _LOG, "DebugFormat|InfoFormat|WarnFormat|ErrorFormat|FatalFormat", all_args=True)
    + _each("log", "Trace", ("System.Diagnostics.Trace",), "Write|WriteLine", args=(0,))
    + _each("log", "Trace", ("System.Diagnostics.Trace",), "TraceInformation|TraceWarning|TraceError",
            all_args=True)
)


# -- sanitizers -----------------------------------------------------------

@dataclass(frozen=True)
class Sanitizer:
    name: str
    kinds: frozenset[str]            # sink kinds the result is safe for; "*" = all
    types: tuple[str, ...]           # full type names; empty = any receiver
    member: str                      # regex over the member / function name
    crlf: bool = False               # `Replace` call that removes CR / LF (tracked per value)
    bare_ok: bool = False            # a receiver-less call by this name matches when `sym` is absent (VB `Val`)


_NUM = ("System.Int16", "System.Int32", "System.Int64", "System.Decimal", "System.Double", "System.Boolean",
        "System.DateTime", "System.Guid", "System.Byte", "System.Single", "System.UInt16", "System.UInt32",
        "System.UInt64")
_ALL = frozenset({"*"})
_XSS = frozenset({"xss"})

SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer("Parse", _ALL, _NUM, r"(?i)^(Parse|TryParse|ParseExact|TryParseExact)$"),
    Sanitizer("Convert.ToNumber", _ALL, ("System.Convert",),
              r"(?i)^To(Int16|Int32|Int64|Decimal|Double|Boolean|DateTime)$"),
    Sanitizer("Val", _ALL, ("Microsoft.VisualBasic.Conversion",), r"(?i)^Val$", bare_ok=True),
    Sanitizer("HttpUtility.HtmlEncode", _XSS,
              ("System.Web.HttpUtility", "System.Web.HttpServerUtility", "System.Web.HttpServerUtilityBase",
               "System.Net.WebUtility", "System.Web.Security.AntiXss.AntiXssEncoder",
               "System.Web.Security.AntiXss.Encoder", "Microsoft.Security.Application.Encoder",
               "System.Web.Util.HttpEncoder"),
              r"(?i)^(Html(Attribute)?Encode|JavaScript(String)?Encode)$"),
    Sanitizer("Path.GetFileName", frozenset({"path"}), ("System.IO.Path",), r"(?i)^GetFileName$"),
    Sanitizer("ldap-escape", frozenset({"ldap"}), (), r"(?i)^[A-Za-z0-9_]*ldap.*(escape|encode)"),
    # Removing CR/LF: handled specially (needs both removed; see taint.py), kinds come from the markers.
    Sanitizer("Replace-CRLF", frozenset(), (), r"(?i)^Replace$", crlf=True),
)
# HttpUtility.UrlEncode deliberately has no entry: it does not stop off-site redirects.

# `.Count` / `.Length` read a number, whatever the receiver held.
CLEANSING_MEMBERS = frozenset({"count", "length"})

# Casts to these types make the value safe for every sink kind.
SAFE_CAST_TYPES = frozenset({
    "int", "uint", "long", "ulong", "short", "ushort", "byte", "sbyte", "decimal", "double", "float", "single",
    "bool", "boolean", "integer", "uinteger", "date", "datetime", "guid", "int16", "int32", "int64", "uint16",
    "uint32", "uint64",
})

# C# keyword / VB alias -> BCL simple name, for the receiver-text fallback.
TYPE_ALIASES = {
    "int": "Int32", "integer": "Int32", "long": "Int64", "short": "Int16", "bool": "Boolean", "double": "Double",
    "decimal": "Decimal", "float": "Single", "single": "Single", "byte": "Byte", "date": "DateTime",
    "uint": "UInt32", "ulong": "UInt64", "ushort": "UInt16", "string": "String", "object": "Object",
}


# -- string helpers (propagate receiver + argument taint) -----------------

@dataclass(frozen=True)
class Helper:
    types: tuple[str, ...]           # simple type names; empty = instance method on anything
    member: str                      # regex over the method name
    bare: bool = False               # also matches a receiver-less call (VB module functions)


_VB_STR = r"(?i)^(Mid|Left|Right|Trim|LTrim|RTrim|UCase|LCase|Replace|Join|Split|StrConv|Format|StrReverse)$"
STRING_HELPERS: tuple[Helper, ...] = (
    Helper((), r"(?i)^(ToString|Trim|TrimStart|TrimEnd|ToUpper|ToLower|ToUpperInvariant|ToLowerInvariant|"
                r"Substring|Replace|PadLeft|PadRight|Insert|Remove|Append|AppendFormat|AppendLine|AppendJoin|"
                r"Split|Normalize|GetString|GetBytes|GetChars)$"),
    Helper(("String", "string"), r"(?i)^(Format|Concat|Join|Copy)$"),
    Helper(("Path",), r"(?i)^(Combine|GetFullPath)$"),
    Helper((), _VB_STR, bare=True),
    Helper(("Strings",), _VB_STR),
    Helper(("HttpUtility", "WebUtility"), r"(?i)^(UrlDecode|HtmlDecode|UrlEncode|UrlPathEncode)$"),
    Helper(("Uri",), r"(?i)^(UnescapeDataString|EscapeDataString|EscapeUriString)$"),
    Helper(("Convert",), r"(?i)^(FromBase64String|ToBase64String)$"),
    Helper(("Regex",), r"(?i)^(Replace|Escape|Unescape)$"),
)
# External instance calls on a tainted receiver propagate its taint unless the member is
# one of these (they return a bool / number / type, not data derived from the text).
NON_PROPAGATING = frozenset({
    "contains", "startswith", "endswith", "equals", "compareto", "indexof", "lastindexof", "any", "count",
    "length", "ismatch", "hasvalue", "gethashcode", "gettype",
})
# Collection mutators: their arguments are folded into the receiver variable.
MUTATORS = frozenset({"add", "addrange", "push", "enqueue"})
# `sb.Append(x)` also folds x into the variable that holds `sb`.
APPEND_LIKE = frozenset({"append", "appendformat", "appendline", "appendjoin", "insert"})


# -- guards ---------------------------------------------------------------

@dataclass(frozen=True)
class Guard:
    """An `if` condition that proves the guarded value safe inside the then-branch.
    `shape` selects the matcher in taint.py."""
    name: str
    shape: str                       # islocalurl | contains | indexof | startswith-fullpath
    cleanses: frozenset[str]


GUARDS: tuple[Guard, ...] = (
    Guard("Url.IsLocalUrl", "islocalurl", frozenset({"redirect"})),
    Guard("collection.Contains", "contains", _ALL),
    Guard("Array.IndexOf", "indexof", _ALL),
    Guard("Path.GetFullPath+StartsWith", "startswith-fullpath", frozenset({"path"})),
)
