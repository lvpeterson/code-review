using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.Text.RegularExpressions;
using System.Web.Mvc;

namespace Cs.Fixes
{
    // Source / sink / sanitizer table edges.
    public class Tables : Controller
    {
        private SqlConnection _c;

        public void ReflectPathInfo() { Response.Write(Request.PathInfo); }

        public void ReflectPath() { Response.Write(Request.Path); }

        public void ReflectUserAgent() { Response.Write(Request.UserAgent); }

        public void ReflectContentType() { Response.Write(Request.ContentType); }

        public void ReflectMethod() { Response.Write(Request.HttpMethod); }

        public void RegexLoose()
        {
            var v = Request["v"];
            if (Regex.IsMatch(v, @"^[a-z]+$")) { var cmd = new SqlCommand(v, _c); }
        }

        public void RegexStrict()
        {
            var v = Request["v"];
            if (Regex.IsMatch(v, @"^[a-z]+\z")) { var cmd = new SqlCommand(v, _c); }
        }

        public void RegexGreedy()
        {
            var v = Request["v"];
            if (Regex.IsMatch(v, @"^.*\z")) { var cmd = new SqlCommand(v, _c); }
        }

        public void RegexTopLevelAlt()
        {
            var v = Request["v"];
            if (Regex.IsMatch(v, @"^a|b\z")) { var cmd = new SqlCommand(v, _c); }
        }

        public void RegexWildcardEquiv()
        {
            var v = Request["v"];
            if (Regex.IsMatch(v, @"^[\s\S]*\z")) { var cmd = new SqlCommand(v, _c); }
        }

        public void RegexGroupedAlt()
        {
            var v = Request["v"];
            if (Regex.IsMatch(v, @"^(a|b)\z")) { var cmd = new SqlCommand(v, _c); }
        }

        public void LogFormatArgs()
        {
            log4net.ILog log = null;
            log.InfoFormat("user {0}", Request["a"]);
        }

        public void LogFormatConst()
        {
            log4net.ILog log = null;
            log.InfoFormat("user {0}", "const");
        }

        public void TraceFormatArgs()
        {
            Trace.TraceInformation("user {0}", Request["a"]);
        }

        private static string NoopLdapEscape(string s) { return s; }

        private static string RealLdapEscape(string s) { return s.Replace("*", "\\2a").Replace("(", "\\28"); }

        public void LdapNoop()
        {
            var s = new DirectorySearcher();
            s.Filter = "(cn=" + NoopLdapEscape(Request["v"]) + ")";
        }

        public void LdapReal()
        {
            var s = new DirectorySearcher();
            s.Filter = "(cn=" + RealLdapEscape(Request["v"]) + ")";
        }
    }
}
