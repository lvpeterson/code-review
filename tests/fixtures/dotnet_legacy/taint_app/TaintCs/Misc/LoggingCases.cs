using System;
using System.Web.Mvc;
using System.Web.Security;
using log4net;

namespace TaintCs.Misc
{
    public class LoginModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }

    // LOG-003: a secret-named value reaches a log call.
    public class LogLeakController : Controller
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(LogLeakController));
        private static readonly ILog AuditTrail = LogManager.GetLogger("audit");

        public ActionResult Direct(LoginModel model)
        {
            Log.Info("password is " + model.Password);
            return Content("ok");
        }

        public ActionResult Interp(LoginModel model)
        {
            Log.Debug($"login {model.UserName} {model.Password}");
            return Content("ok");
        }

        public ActionResult Format(string user, string pwd)
        {
            Log.InfoFormat("user {0} pwd {1}", user, pwd);
            return Content("ok");
        }

        public ActionResult ViaLocal(LoginModel model)
        {
            var pw = model.Password;
            Log.Warn(pw);
            return Content("ok");
        }

        public ActionResult TraceToken(string apiToken)
        {
            System.Diagnostics.Trace.WriteLine("token=" + apiToken);
            return Content("ok");
        }

        public ActionResult NamedArg(string clientSecret)
        {
            AuditTrail.Error(message: "key " + clientSecret);
            return Content("ok");
        }

        // Not leaks: no secret value reaches the log.
        public ActionResult UserOnly(LoginModel model)
        {
            Log.Info("login for " + model.UserName);
            return Content("ok");
        }

        public ActionResult LiteralWord()
        {
            Log.Info("password reset requested");
            return Content("ok");
        }

        public ActionResult LengthOnly(LoginModel model)
        {
            Log.Info("password length " + model.Password.Length);
            return Content("ok");
        }

        public ActionResult SettingName(Settings settings)
        {
            Log.Info(settings.PasswordMinLength);
            return Content("ok");
        }

        public ActionResult NotALogger(LoginModel model)
        {
            Console.WriteLine(model.Password);
            var sb = new System.Text.StringBuilder();
            sb.Append(model.Password);
            return Content(sb.ToString());
        }
    }

    public class Settings
    {
        public int PasswordMinLength { get; set; }
    }

    // LOG-004: login failure branches with and without a log call.
    public class LoginLogController : Controller
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(LoginLogController));

        public ActionResult Login(LoginModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                ModelState.AddModelError("", "Invalid login");
                return View(m);
            }
            return RedirectToAction("Index");
        }

        public ActionResult LoginLogged(LoginModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                Log.Warn("failed login for " + m.UserName);
                ModelState.AddModelError("", "Invalid login");
                return View(m);
            }
            return RedirectToAction("Index");
        }

        public ActionResult LoginLogBefore(LoginModel m)
        {
            Log.Info("login attempt");
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                ModelState.AddModelError("", "Invalid login");
                return View(m);
            }
            return RedirectToAction("Index");
        }

        public ActionResult LoginNested(LoginModel m, bool verbose)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                if (verbose) { Log.Warn("failed"); }
                ModelState.AddModelError("", "Invalid login");
                return View(m);
            }
            return RedirectToAction("Index");
        }

        public ActionResult LoginTail(LoginModel m)
        {
            if (Membership.ValidateUser(m.UserName, m.Password))
            {
                FormsAuthentication.SetAuthCookie(m.UserName, false);
                return Redirect("/");
            }
            ModelState.AddModelError("", "Invalid login");
            return View(m);
        }

        public ActionResult LoginTailLogged(LoginModel m)
        {
            if (Membership.ValidateUser(m.UserName, m.Password))
            {
                FormsAuthentication.SetAuthCookie(m.UserName, false);
                return Redirect("/");
            }
            Log.Warn("failed login for " + m.UserName);
            ModelState.AddModelError("", "Invalid login");
            return View(m);
        }

        public ActionResult LoginHelperLogs(LoginModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                LogFailure(m.UserName);
                ModelState.AddModelError("", "Invalid login");
                return View(m);
            }
            return RedirectToAction("Index");
        }

        public ActionResult LoginHelperSilent(LoginModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                NoteFailure(m.UserName);
                ModelState.AddModelError("", "Invalid login");
                return View(m);
            }
            return RedirectToAction("Index");
        }

        public ActionResult Logout()
        {
            ModelState.AddModelError("", "Invalid session");
            return RedirectToAction("Index");
        }

        // WebForms-style failure handlers.
        public void Login1_LoginError(object sender, EventArgs e)
        {
            ViewBag.Message = "Invalid login";
        }

        public void Login2_LoginError(object sender, EventArgs e)
        {
            Log.Warn("login error");
            ViewBag.Message = "Invalid login";
        }

        private void LogFailure(string user)
        {
            Log.Warn("failed login for " + user);
        }

        private void NoteFailure(string user)
        {
            var seen = user;
        }
    }
}
