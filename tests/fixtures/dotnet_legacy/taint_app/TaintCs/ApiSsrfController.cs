using System.Net;
using System.Web.Http;

namespace Cs.Sinks
{
    // Web API route reaching an SSRF sink (tags the finding API7:2023).
    public class ApiSsrfController : ApiController
    {
        public string Get(string url)
        {
            var c = new WebClient();
            return c.DownloadString(url);
        }
    }
}
