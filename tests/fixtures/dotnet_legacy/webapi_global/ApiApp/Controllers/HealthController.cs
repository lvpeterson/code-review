using System.Web.Http;

namespace ApiApp.Controllers
{
    public class HealthController : ApiController
    {
        [AllowAnonymous]
        public string Get() { return "ok"; }
    }
}
