using System.Data.SqlClient;

namespace Cs.Layered
{
    // A <-> B where B reads a request source and calls A.
    public static class CycleSrc
    {
        public static void A(string s, SqlConnection c)
        {
            var cmd = new SqlCommand("select " + s, c);
            B(c);
        }

        public static void B(SqlConnection c)
        {
            string q = System.Web.HttpContext.Current.Request.QueryString["q"];
            A(q, c);
        }
    }
}
