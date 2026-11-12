using System.Data.SqlClient;
using System.Web;

namespace Cs
{
    public class Out : System.Web.UI.Page
    {
        // HtmlEncode makes the value safe for the page, not for the query.
        public void Encoded(SqlConnection conn)
        {
            string q = Request.QueryString["q"];
            Response.Write(HttpUtility.HtmlEncode(q));
            var cmd = new SqlCommand();
            cmd.CommandText = "select * from t where n = '" + HttpUtility.HtmlEncode(q) + "'";
        }
    }
}
