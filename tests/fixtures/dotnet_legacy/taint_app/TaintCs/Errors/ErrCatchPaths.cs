using System;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;

namespace TaintCs.Errors
{
    // Which paths through a catch deny: only a deny on every path counts.
    public class CpController : Controller
    {
        private RfLog _log = new RfLog();
        private bool _debug;
        private void Work() { }

        // -- fail-open: some path falls out of the catch ------------------------------------
        public ActionResult A1()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { if (ex is InvalidOperationException) return new HttpUnauthorizedResult(); }
            return View();
        }

        public ActionResult A2()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { if (_debug) Response.End(); }
            return View();
        }

        public ActionResult A3()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { if (_debug) { Response.Redirect("~/Login"); } }
            return View();
        }

        public ActionResult B1()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { Response.Redirect("~/Login", endResponse: false); }
            Work();
            return View();
        }

        public ActionResult B2()
        {
            bool stop = false;
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { Response.Redirect("~/Login", endResponse: stop); }
            Work();
            return View();
        }

        // -- safe: every path denies ----------------------------------------------------------
        public ActionResult S1()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { if (_debug) return new HttpUnauthorizedResult(); else throw new HttpException(403, "no"); }
            return View();
        }

        public ActionResult S2()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { if (_debug) { _log.Error(null); } Response.End(); }
            return View();
        }

        public ActionResult S3()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { Response.Redirect("~/Login", endResponse: true); }
            return View();
        }

        // The status is the last thing the catch does and nothing follows the try.
        public void C1() { try { if (!User.IsInRole("a")) Response.End(); } catch (Exception ex) { Response.StatusCode = 401; } }
    }

    public class CpBool
    {
        public bool TrueOnAPath(IPrincipal u, bool x)
        {
            try { if (!u.IsInRole("a")) throw new InvalidOperationException(); }
            catch (Exception ex) { if (x) return true; }
            return false;
        }

        public bool DenyOnEveryPath(IPrincipal u, bool x)
        {
            try { if (!u.IsInRole("a")) throw new InvalidOperationException(); }
            catch (Exception ex) { if (x) return false; else throw; }
            return true;
        }
    }

    public class CpStatic
    {
        static CpStatic() { try { Init(); } catch { } }
        public CpStatic() { try { Init(); } catch { } }
        private static void Init() { }
    }
}

namespace TaintCs.Errors
{
    public static class CpStaticClass
    {
        static CpStaticClass() { try { Init(); } catch { } }
        private static void Init() { }
    }
}
