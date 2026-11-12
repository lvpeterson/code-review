using System.Data.SqlClient;

namespace Cs
{
    public class Variadic
    {
        public static void F(SqlConnection c, params string[] a)
        {
            var cmd = new SqlCommand(string.Join(",", a), c);
        }

        public void Dirty(SqlConnection c)
        {
            F(c, "k", System.Web.HttpContext.Current.Request.QueryString["q"]);
        }

        public void Clean(SqlConnection c)
        {
            F(c, "k", "v");
        }
    }
}
