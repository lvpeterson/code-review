using System.Collections.Generic;

namespace Cs
{
    public class Guards : System.Web.UI.Page
    {
        // A text search inside tainted text is not a whitelist.
        public void StringContains()
        {
            string q = Request.QueryString["q"];
            string q2 = Request.QueryString["r"];
            if (q2.Contains(q))
            {
                Response.Redirect(q);
            }
        }

        // Untyped locals initialised from string expressions are strings too.
        public void InferredStringContains()
        {
            var s = "/home" + "/about";
            string q = Request.QueryString["q"];
            if (s.Contains(q))
            {
                Response.Redirect(q);
            }
        }

        public void ListContains()
        {
            var allowed = new List<string> { "/home", "/about" };
            string q = Request.QueryString["q"];
            if (allowed.Contains(q))
            {
                Response.Redirect(q);
            }
        }
    }
}
