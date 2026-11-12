using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Net;
using System.Web.Mvc;
using System.Xml;

namespace Cs.Sinks
{
    // One action per kind: each reaches a <Kind>Bad (untrusted input at the sink) and a <Kind>Good
    // (sanitized or guarded) method, so findings are proven and attach to a route.
    public class CodeSinksController : Controller
    {
        public ActionResult Cmd(string v) { CmdBad(v); CmdGood(v); return null; }
        public ActionResult Ldap(string v) { LdapBad(v); LdapGood(v); return null; }
        public ActionResult XPath(string v) { XpathBad(v); XpathGood(v); return null; }
        public ActionResult Header(string v) { HeaderBad(v); HeaderGood(v); return null; }
        public ActionResult Xss(string v) { XssBad(v); XssGood(v); return null; }
        public ActionResult PathT(string v) { PathBad(v); PathGood(v); return null; }
        public ActionResult Redir(string v) { RedirectBad(v); RedirectGood(v); return null; }
        public ActionResult Ssrf(string v) { SsrfBad(v); SsrfGood(v); return null; }
        public ActionResult Log(string v) { LogBad(v); LogGood(v); return null; }

        private void CmdBad(string v) { Process.Start(v); }

        private void CmdGood(string v)
        {
            var allowed = new List<string> { "notepad.exe", "calc.exe" };
            if (allowed.Contains(v))
            {
                Process.Start(v);
            }
        }

        private void LdapBad(string v)
        {
            var s = new DirectorySearcher();
            s.Filter = "(cn=" + v + ")";
        }

        // RFC 4515 escape: backslash first, then the other special characters.
        private static string LdapEscape(string s)
        {
            return s.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29")
                    .Replace("\0", "\\00");
        }

        private void LdapGood(string v)
        {
            var s = new DirectorySearcher();
            s.Filter = "(cn=" + LdapEscape(v) + ")";
        }

        private void XpathBad(string v)
        {
            var d = new XmlDocument();
            d.SelectNodes("//user[@name='" + v + "']");
        }

        private void XpathGood(string v)
        {
            var d = new XmlDocument();
            d.SelectNodes("//user[@id=" + int.Parse(v) + "]");
        }

        private void HeaderBad(string v) { Response.AddHeader("X-Note", v); }

        private void HeaderGood(string v)
        {
            Response.AddHeader("X-Note", v.Replace("\r", "").Replace("\n", ""));
        }

        private void XssBad(string v) { Response.Write("<p>" + v + "</p>"); }

        private void XssGood(string v)
        {
            Response.Write("<p>" + System.Web.HttpUtility.HtmlEncode(v) + "</p>");
        }

        private void PathBad(string v) { System.IO.File.ReadAllText(@"App_Data\" + v); }

        private void PathGood(string v)
        {
            System.IO.File.ReadAllText(Path.Combine("App_Data", Path.GetFileName(v)));
        }

        private ActionResult RedirectBad(string v) { return Redirect(v); }

        private ActionResult RedirectGood(string v)
        {
            if (Url.IsLocalUrl(v))
            {
                return Redirect(v);
            }
            return null;
        }

        private void SsrfBad(string v)
        {
            var c = new WebClient();
            c.DownloadString(v);
        }

        private void SsrfGood(string v)
        {
            var c = new WebClient();
            c.DownloadString("https://example.invalid/api/" + int.Parse(v));
        }

        private void LogBad(string v)
        {
            log4net.ILog log = null;
            log.Info("login " + v);
        }

        private void LogGood(string v)
        {
            log4net.ILog log = null;
            log.Info("login " + v.Replace("\r", "").Replace("\n", ""));
        }
    }
}
