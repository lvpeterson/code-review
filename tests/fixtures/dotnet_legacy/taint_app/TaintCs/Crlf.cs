namespace Cs
{
    public class Crlf : System.Web.UI.Page
    {
        public void OnlyCr()
        {
            Response.AddHeader("X-Note", Request.QueryString["v"].Replace("\r", ""));
        }

        public void BothViaChain()
        {
            Response.AddHeader("X-Note", Request.QueryString["v"].Replace("\r", "").Replace("\n", ""));
        }

        // Removing the pair, then a lone CR, still leaves a lone LF.
        public void PairThenCr()
        {
            Response.AddHeader("X-Note", Request.QueryString["v"].Replace("\r\n", "").Replace("\r", ""));
        }

        public void SwapLfForCr()
        {
            Response.AddHeader("X-Note", Request.QueryString["v"].Replace("\r", "").Replace("\n", "\r"));
        }
    }
}
