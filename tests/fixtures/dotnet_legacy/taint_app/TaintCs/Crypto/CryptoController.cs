using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;

namespace TaintCs.Crypto
{
    public class CryptoController : Controller
    {
        [AllowAnonymous]
        public ActionResult Digest(string password)
        {
            var md5 = MD5.Create();
            return Content(System.Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password))));
        }
    }
}
