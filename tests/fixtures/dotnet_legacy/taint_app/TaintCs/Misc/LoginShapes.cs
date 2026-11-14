using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Security;
using log4net;

namespace TaintCs.Misc
{
    public class AuthResultModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }

    // LOG-004 / DES-001: login handlers recognised by shape and context, with and without a log call.
    public class LoginShapesController : Controller
    {
        private static readonly ILog Log = LogManager.GetLogger(typeof(LoginShapesController));
        private ApplicationUserManager UserManager;

        public ActionResult LoginJson(AuthResultModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                return Json(new { success = false, message = "no" });
            }
            return Json(new { success = true });
        }

        public ActionResult LoginJsonLogged(AuthResultModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                Log.Warn("failed login " + m.UserName);
                return Json(new { success = false, message = "no" });
            }
            return Json(new { success = true });
        }

        public ActionResult LoginContent(AuthResultModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                return Content("denied");
            }
            return Redirect("/");
        }

        public ActionResult LoginRedirect(AuthResultModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                return RedirectToAction("Login", new { error = 1 });
            }
            return Redirect("/");
        }

        public ActionResult LoginTempData(AuthResultModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                TempData["LoginError"] = "bad";
                return View(m);
            }
            return Redirect("/");
        }

        public async Task<ActionResult> LoginNullUser(AuthResultModel m)
        {
            var user = await UserManager.FindAsync(m.UserName, m.Password);
            if (user == null)
            {
                return View(m);
            }
            return Redirect("/");
        }

        public async Task<ActionResult> LoginNullUserLogged(AuthResultModel m)
        {
            var user = await UserManager.FindAsync(m.UserName, m.Password);
            if (user == null)
            {
                Log.Warn("unknown user or bad password");
                return View(m);
            }
            return Redirect("/");
        }

        // WebForms Login control handler: no branch at all, and no log call anywhere.
        public void Login1_Authenticate(object sender, AuthenticateEventArgs e)
        {
            e.Authenticated = Membership.ValidateUser("u", "p");
        }

        public void Login3_Authenticate(object sender, AuthenticateEventArgs e)
        {
            Log.Info("authenticating");
            e.Authenticated = Membership.ValidateUser("u", "p");
        }
    }

    // Login by controller context: the action is just Post.
    public class AuthController : ApiController
    {
        public HttpResponseMessage Post(AuthResultModel m)
        {
            if (!Membership.ValidateUser(m.UserName, m.Password))
            {
                return Request.CreateResponse(HttpStatusCode.Unauthorized);
            }
            return Request.CreateResponse(HttpStatusCode.OK);
        }
    }

    public class AccountShapesController : Controller
    {
        [HttpPost]
        public ActionResult Post(AuthResultModel credentials)
        {
            if (!Membership.ValidateUser(credentials.UserName, credentials.Password))
            {
                return Content("denied");
            }
            return Redirect("/");
        }

        // Not a login: no credential parameters.
        [HttpPost]
        public ActionResult Post(int id)
        {
            return Content("denied");
        }
    }

    public class ApplicationOAuthProvider
    {
        private ApplicationUserManager userManager;

        public async Task GrantResourceOwnerCredentials(OAuthContext context)
        {
            var user = await userManager.FindAsync(context.UserName, context.Password);
            if (user == null)
            {
                context.SetError("invalid_grant", "bad");
                return;
            }
        }
    }

    public class OAuthContext
    {
        public string UserName;
        public string Password;
        public void SetError(string a, string b) { }
    }
}
