using System.Data.SqlClient;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;

namespace TaintCs.Misc
{
    // CONSUME-001: more client call shapes, and a loopback look-alike.
    public class OutboundExtras
    {
        private readonly HttpClient client = new HttpClient();

        public Task<HttpResponseMessage> PostJson()
        {
            return client.PostAsJsonAsync("http://json.example.net/in", new { a = 1 });
        }

        public Task<HttpResponseMessage> PutXml()
        {
            return client.PutAsXmlAsync("http://xml.example.net/in", new { a = 1 });
        }

        public Task<HttpResponseMessage> SendMessage()
        {
            return client.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://send.example.net/x"));
        }

        public Task<string> LoopbackLookalike()
        {
            return client.GetStringAsync("http://localhost:80@lookalike.example.net/x");
        }

        public Task<string> LoopbackSubdomain()
        {
            return client.GetStringAsync("http://localhost.lookalike.example.net/x");
        }

        public Task<string> RealLoopback()
        {
            return client.GetStringAsync("http://localhost:8080/x");
        }
    }

    // CONSUME-002: the INCOMING request body is request input, never an external source.
    public class IncomingBodyController : ApiController
    {
        public async Task<IHttpActionResult> Post()
        {
            var body = await Request.Content.ReadAsStringAsync();
            var cmd = new SqlCommand("SELECT * FROM T WHERE N='" + body + "'");
            return Ok();
        }
    }
}
