using System.Web.Http;

namespace ApiApp.Controllers
{
    public class ValuesController : ApiController
    {
        public string[] Get() { return new[] { "a", "b" }; }
    }
}
