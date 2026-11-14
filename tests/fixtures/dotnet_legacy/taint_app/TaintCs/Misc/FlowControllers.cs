using System;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Security;

namespace TaintCs.Misc
{
    public class RegisterModel
    {
        public string Email { get; set; }
        public string Captcha { get; set; }
    }

    // A rate limiter that does something, and one that does nothing.
    public class RateLimitAttribute : ActionFilterAttribute
    {
        public int Max { get; set; }
        public RateLimitAttribute(int max) { Max = max; }
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (Counter.Hit(filterContext.HttpContext.Request.UserHostAddress) > Max)
            {
                filterContext.Result = new HttpStatusCodeResult(429);
            }
        }
    }

    public class NopThrottleAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
        }
    }

    public static class Counter
    {
        public static int Hit(string key) { return 0; }
    }

    public class AuthService
    {
        public bool Login(LoginModel m) { return Membership.ValidateUser(m.UserName, m.Password); }
    }

    public class WeakService
    {
        public bool Check(LoginModel m) { return m.Password == "x"; }
    }

    [RateLimit(10)]
    public abstract class ThrottledBase : Controller
    {
    }

    // Protected by the attribute on the base controller: nothing here is reported.
    public class ThrottledAccountController : ThrottledBase
    {
        [HttpPost]
        public ActionResult Login(LoginModel m) { return View(m); }

        [HttpPost]
        public ActionResult Register(RegisterModel m) { return View(m); }
    }

    public class FlowController : Controller
    {
        private readonly bool debug = false;
        private readonly AuthService _auth = new AuthService();
        private readonly WeakService _weak = new WeakService();
        private ApplicationSignInManager SignInManager;
        private ApplicationUserManager UserManager;

        // No lockout: FindAsync only checks the password.
        [HttpPost]
        public async Task<ActionResult> Login(LoginModel m)
        {
            var user = await UserManager.FindAsync(m.UserName, m.Password);
            return user == null ? View(m) : (ActionResult)Redirect("/");
        }

        [HttpGet]
        public ActionResult Login() { return View(); }

        [HttpPost]
        [RateLimit(5)]
        public ActionResult Register(RegisterModel m) { return View(m); }

        [HttpPost]
        public ActionResult ResetPassword(RegisterModel m) { return View(m); }

        // The limiter is on a different action only.
        [RateLimit(3)]
        public ActionResult Index() { return View(); }

        [HttpPost]
        public ActionResult ForgotPassword(RegisterModel m) { return View(m); }

        [HttpPost]
        [NopThrottle]
        public ActionResult ChangePassword(RegisterModel m) { return View(m); }

        [HttpPost]
        public async Task<ActionResult> LoginLockout(LoginModel m)
        {
            var r = await SignInManager.PasswordSignInAsync(m.UserName, m.Password, false, shouldLockout: true);
            return View(m);
        }

        [HttpPost]
        public async Task<ActionResult> LoginNoLock(LoginModel m)
        {
            var r = await SignInManager.PasswordSignInAsync(m.UserName, m.Password, false, shouldLockout: false);
            return View(m);
        }

        [HttpPost]
        public async Task<ActionResult> LoginNoLockPositional(LoginModel m)
        {
            var r = await SignInManager.PasswordSignInAsync(m.UserName, m.Password, false, false);
            return View(m);
        }

        [HttpPost]
        public async Task<ActionResult> LoginLockPositional(LoginModel m)
        {
            var r = await SignInManager.PasswordSignInAsync(m.UserName, m.Password, false, true);
            return View(m);
        }

        [HttpPost]
        public async Task<ActionResult> LoginDebugOnly(LoginModel m)
        {
            if (debug)
            {
                var r = await SignInManager.PasswordSignInAsync(m.UserName, m.Password, false, shouldLockout: true);
            }
            return View(m);
        }

        [HttpPost]
        public async Task<ActionResult> LoginDeadBranch(LoginModel m)
        {
            if (false)
            {
                var r = await SignInManager.PasswordSignInAsync(m.UserName, m.Password, false, shouldLockout: true);
            }
            return View(m);
        }

        [HttpPost]
        public ActionResult LoginMembership(LoginModel m)
        {
            return Membership.ValidateUser(m.UserName, m.Password) ? (ActionResult)Redirect("/") : View(m);
        }

        [HttpPost]
        public ActionResult LoginViaService(LoginModel m)
        {
            return _auth.Login(m) ? (ActionResult)Redirect("/") : View(m);
        }

        [HttpPost]
        public ActionResult LoginViaWeakService(LoginModel m)
        {
            return _weak.Check(m) ? (ActionResult)Redirect("/") : View(m);
        }

        [HttpPost]
        public ActionResult LoginCaptcha(LoginModel m)
        {
            if (!ReCaptcha.Validate(m.UserName))
            {
                return View(m);
            }
            return Redirect("/");
        }

        [HttpPost]
        public async Task<ActionResult> LoginAfterGuard(LoginModel m)
        {
            if (!ModelState.IsValid) { return View(m); }
            var r = await SignInManager.PasswordSignInAsync(m.UserName, m.Password, false, shouldLockout: true);
            return View(m);
        }

        [HttpPost]
        public async Task<ActionResult> LoginInsideValid(LoginModel m)
        {
            if (ModelState.IsValid)
            {
                var r = await SignInManager.PasswordSignInAsync(m.UserName, m.Password, false, shouldLockout: true);
            }
            return View(m);
        }

        [HttpPost]
        public ActionResult Checkout(RegisterModel m) { return View(m); }

        [HttpPost]
        public ActionResult PayInvoice(RegisterModel m) { return View(m); }

        public ActionResult Logout() { return Redirect("/"); }
    }

    public class AccountApiController : ApiController
    {
        [HttpPost]
        public IHttpActionResult Login(LoginModel m) { return Ok(); }

        [HttpPost]
        public IHttpActionResult Register(RegisterModel m) { return Ok(); }
    }

    public class ApplicationSignInManager
    {
        public Task<int> PasswordSignInAsync(string u, string p, bool persist, bool shouldLockout) { return null; }
    }

    public class ApplicationUserManager
    {
        public Task<object> FindAsync(string u, string p) { return null; }
    }

    public static class ReCaptcha
    {
        public static bool Validate(string response) { return true; }
    }
}
