using System.Data.SqlClient;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Mvc;
using Newtonsoft.Json;

namespace TaintCs.Misc
{
    public class UpstreamOrder
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public string Next { get; set; }
        public string Id { get; set; }
    }

    // CONSUME-002: an outbound response body used without validation. The upstream URL is a
    // constant, so no request input reaches these sinks: only the external taint does.
    public class ExternalFlowController : Controller
    {
        private readonly HttpClient client = new HttpClient();

        public async Task<ActionResult> SqlFromTyped()
        {
            var resp = await client.GetAsync("https://upstream.example.net/order");
            var order = await resp.Content.ReadAsAsync<UpstreamOrder>();
            var cmd = new SqlCommand("SELECT * FROM T WHERE N='" + order.Name + "'");
            return Content("ok");
        }

        public async Task<ActionResult> PathFromJson()
        {
            var resp = await client.GetAsync("https://upstream.example.net/order");
            var body = await resp.Content.ReadAsStringAsync();
            var o = JsonConvert.DeserializeObject<UpstreamOrder>(body);
            return Content(File.ReadAllText(o.Path));
        }

        public async Task<ActionResult> RedirectFromJson()
        {
            var body = await client.GetStringAsync("https://upstream.example.net/order");
            var o = JsonConvert.DeserializeObject<UpstreamOrder>(body);
            return Redirect(o.Next);
        }

        public ActionResult SqlFromWebClient()
        {
            var s = new WebClient().DownloadString("https://upstream.example.net/name");
            var cmd = new SqlCommand("SELECT * FROM T WHERE N='" + s + "'");
            return Content("ok");
        }

        // Not reported: the value reaches no sink / is parameterized / is a number.
        public async Task<ActionResult> Parameterized()
        {
            var resp = await client.GetAsync("https://upstream.example.net/order");
            var order = await resp.Content.ReadAsAsync<UpstreamOrder>();
            var cmd = new SqlCommand("SELECT * FROM T WHERE N=@n");
            cmd.Parameters.AddWithValue("@n", order.Name);
            return Content("ok");
        }

        public async Task<ActionResult> Numeric()
        {
            var resp = await client.GetAsync("https://upstream.example.net/order");
            var order = await resp.Content.ReadAsAsync<UpstreamOrder>();
            int id = int.Parse(order.Id);
            var cmd = new SqlCommand("SELECT * FROM T WHERE Id=" + id);
            return Content("ok");
        }
    }

    // Not routed and never called: an external-only flow here must not surface as an unproven
    // request-source row either.
    public class ExternalOnlyHelper
    {
        public void Run()
        {
            var s = new WebClient().DownloadString("https://upstream.example.net/name");
            var cmd = new SqlCommand("SELECT * FROM T WHERE N='" + s + "'");
        }
    }
}
