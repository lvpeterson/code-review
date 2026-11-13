using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace TaintCs.Account
{
    public class AccountUser
    {
        public string Name { get; set; }
        public string Password { get; set; }
        public string PasswordHash { get; set; }
    }

    public class LoginModel
    {
        public string Name { get; set; }
        public string Password { get; set; }
        public string ConfirmPassword { get; set; }
    }

    public class AccountController : Controller
    {
        public ActionResult LogOff()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");
        }

        public ActionResult LogOffSafe()
        {
            FormsAuthentication.SignOut();
            Session.Abandon();
            return RedirectToAction("Index", "Home");
        }

        public ActionResult SignOutViaHelper()
        {
            HttpContext.GetOwinContext().Authentication.SignOut();
            Wipe();
            return RedirectToAction("Index", "Home");
        }

        private void Wipe()
        {
            Session.Clear();
        }

        [HttpPost]
        public ActionResult Login(LoginModel model, AccountUser user)
        {
            if (user.Password == model.Password)
            {
                FormsAuthentication.SetAuthCookie(model.Name, false);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public ActionResult LoginSafe(LoginModel model, AccountUser user)
        {
            if (System.Web.Helpers.Crypto.VerifyHashedPassword(user.PasswordHash, model.Password))
            {
                Session.Abandon();
                FormsAuthentication.SetAuthCookie(model.Name, false);
            }
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public ActionResult LoginCookie(LoginModel model)
        {
            Response.Cookies["ASP.NET_SessionId"].Value = "";
            FormsAuthentication.RedirectFromLoginPage(model.Name, false);
            return null;
        }

        [HttpPost]
        public ActionResult Register(LoginModel model, AccountUser user)
        {
            if (model.Password != model.ConfirmPassword) return View();
            if (model.Password == null || model.Password == "") return View();
            if (string.Equals(user.Password, model.Password)) return View();
            if (user.PasswordHash == model.Password.GetHashCode().ToString()) return View();
            return View();
        }
    }
}
