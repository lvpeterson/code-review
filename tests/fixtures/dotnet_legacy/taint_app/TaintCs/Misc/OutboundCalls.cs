using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace TaintCs.Misc
{
    public static class Endpoints
    {
        public const string LegacyUrl = "http://api.legacy.example.net/v1";
        public static readonly string FeedUrl = "http://feed.example.net/items";
        public const string SecureUrl = "https://api.example.net/v1";
    }

    // CONSUME-001: hard-coded plain-HTTP URLs on outbound calls.
    public class OutboundCalls
    {
        private static readonly string Hooks = "http://hooks.example.net/in";
        private readonly HttpClient client = new HttpClient();

        public Task<string> Plain()
        {
            return new HttpClient().GetStringAsync("http://api.example.net/x");
        }

        public Task<HttpResponseMessage> ViaConst()
        {
            return client.GetAsync(Endpoints.LegacyUrl + "/orders");
        }

        public string ViaField()
        {
            return new WebClient().DownloadString(Endpoints.FeedUrl);
        }

        public Task<HttpResponseMessage> ViaOwnField()
        {
            return client.PostAsync(Hooks, null);
        }

        public WebResponse ViaLocal()
        {
            var url = "http://x.example.net/a";
            return WebRequest.Create(url).GetResponse();
        }

        public HttpClient BaseAddr()
        {
            return new HttpClient { BaseAddress = new Uri("http://base.example.net/") };
        }

        public void BaseAssign()
        {
            client.BaseAddress = new Uri("http://assigned.example.net/");
        }

        public Task<string> Concat(string host)
        {
            return client.GetStringAsync("http://" + host + "/x");
        }

        public Task<string> Interp(string host)
        {
            return client.GetStringAsync($"http://{host}/x");
        }

        public object Rest()
        {
            return new RestClient("http://rest.example.net");
        }

        public Task<string> Secure()
        {
            return client.GetStringAsync("https://api.example.net/x");
        }

        public Task<string> SecureConst()
        {
            return client.GetStringAsync(Endpoints.SecureUrl);
        }

        public Task<string> Local()
        {
            return client.GetStringAsync("http://localhost:5000/x");
        }

        public Task<string> Loopback()
        {
            return client.GetStringAsync("http://127.0.0.1/y");
        }

        public Task<string> FromConfig(string url)
        {
            return client.GetStringAsync(url);
        }
    }

    public class RestClient
    {
        public RestClient(string baseUrl) { }
    }

    public class NotOutboundController : Controller
    {
        // An http:// literal that is not an outbound client call.
        public ActionResult Go()
        {
            var legacy = "http://old.example.net/";
            return Redirect(legacy);
        }
    }
}
