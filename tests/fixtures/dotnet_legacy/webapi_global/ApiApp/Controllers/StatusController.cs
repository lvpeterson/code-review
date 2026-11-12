using System.Web.Http;

namespace ApiApp.Controllers
{
    // AllowAnonymousAttribute is Inherited=true: every subclass skips the global filter.
    [AllowAnonymous]
    public abstract class PublicApiBase : ApiController
    {
    }

    public class StatusController : PublicApiBase
    {
        public string Get() { return "up"; }
    }

    public class PingController : ApiController
    {
        [System.Web.Http.AllowAnonymousAttribute]
        [System.Web.Http.HttpPutAttribute]
        public void Ping(string payload) { }
    }
}
