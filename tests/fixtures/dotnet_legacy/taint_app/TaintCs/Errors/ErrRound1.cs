using System;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;

namespace TaintCs.Errors
{
    // ERR-001 variants: the catch assigns / returns a value that grants access.
    public class R1Auth
    {
        private const bool DefaultAllow = true;
        private const bool DefaultDeny = false;

        private void Cleanup() { }
        private bool Fallback() { return true; }
        private bool Compute() { return Environment.TickCount > 5; }

        public bool B1Basic(IPrincipal u)
        {
            bool authorized = false;
            try { authorized = u.IsInRole("a"); }
            catch { authorized = true; }
            return authorized;
        }

        public bool B1Outer(IPrincipal u, bool flag)
        {
            bool authorized = false;
            if (flag)
            {
                try { authorized = u.IsInRole("a"); }
                catch (Exception) { authorized = true; }
                finally { Cleanup(); }
            }
            if (flag) { Cleanup(); }
            return authorized;
        }

        public bool B1Safe(IPrincipal u)
        {
            bool authorized = false;
            try { authorized = u.IsInRole("a"); }
            catch { authorized = false; }
            return authorized;
        }

        public bool B3Var(IPrincipal u)
        {
            try { return u.IsInRole("a"); }
            catch { var r = true; return r; }
        }

        public bool B3Call(IPrincipal u)
        {
            try { return u.IsInRole("a"); }
            catch { return Fallback(); }
        }

        public bool B3Not(IPrincipal u)
        {
            try { return u.IsInRole("a"); }
            catch { return !false; }
        }

        public bool B3NotAssign(IPrincipal u)
        {
            bool ok = false;
            try { ok = u.IsInRole("a"); }
            catch { ok = !false; }
            return ok;
        }

        public bool B3Const(IPrincipal u)
        {
            try { return u.IsInRole("a"); }
            catch { return DefaultAllow; }
        }

        public bool B3Unknown(IPrincipal u)
        {
            try { return u.IsInRole("a"); }
            catch { return Compute(); }
        }

        public bool B3SafeConst(IPrincipal u)
        {
            try { return u.IsInRole("a"); }
            catch { return DefaultDeny; }
        }
    }

    public class R1Controller : Controller
    {
        private void Work() { }
        private void Log(Exception ex) { }

        public ActionResult B2Log()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch (Exception ex) { Log(ex); }
            return View();
        }

        public ActionResult B2Empty()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { }
            return View();
        }

        public ActionResult B2Safe()
        {
            try { if (!User.IsInRole("a")) return new HttpUnauthorizedResult(); }
            catch { return new HttpUnauthorizedResult(); }
            return View();
        }

        // Name looks like an auth check but the try is unrelated work: still ERR-003.
        public void CheckPermissionsLater()
        {
            try { Work(); }
            catch { }
        }

        // I1: detail assigned in the catch, sunk after the try.
        public ActionResult ErrAfter()
        {
            string err = null;
            try { Work(); }
            catch (Exception ex) { err = ex.Message; }
            return Content(err);
        }

        public ActionResult ErrModelAfter()
        {
            var model = new ErrModel();
            try { Work(); }
            catch (Exception ex) { model.Detail = ex.Message; }
            return View(model);
        }

        // Safe: the carrier is assigned a constant, nothing leaks.
        public ActionResult ErrConstAfter()
        {
            string err = null;
            try { Work(); }
            catch (Exception ex) { err = "failed"; }
            return Content(err);
        }

        public ActionResult RedirectLeak()
        {
            try { Work(); }
            catch (Exception ex) { return Redirect("/e?m=" + ex.Message); }
            return View();
        }

        public ActionResult RedirectActionLeak()
        {
            try { Work(); }
            catch (Exception ex) { return RedirectToAction("Err", new { m = ex.Message }); }
            return View();
        }

        public ActionResult HeaderLeak()
        {
            try { Work(); }
            catch (Exception ex) { Response.AppendHeader("X-Err", ex.Message); }
            return View();
        }

        public void Application_Error()
        {
            var e = Server.GetLastError();
            Response.Write(e.Message);
        }

        // I2: two catches on one line.
        public void TwoOnLine()
        {
            try { Work(); } catch (FormatException) { } catch { }
        }

        public void AfterTwo()
        {
            try { Work(); }
            catch (Exception) { Log(null); }
        }
    }
}
