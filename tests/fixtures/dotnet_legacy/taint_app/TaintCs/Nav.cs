namespace Cs
{
    public class Nav : System.Web.UI.Page
    {
        public void Safe()
        {
            string u = Request.QueryString["next"];
            if (Url.IsLocalUrl(u))
            {
                Response.Redirect(u);
            }
        }

        public void Unsafe()
        {
            string u = Request.QueryString["next"];
            Response.Redirect(u);
        }
    }
}
