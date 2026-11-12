using System.Data.SqlClient;

namespace Cs
{
    public class UsesAccum
    {
        public void Dirty(SqlConnection c)
        {
            var b = new Accum();
            b.Add(System.Web.HttpContext.Current.Request.QueryString["q"]);
            var cmd = new SqlCommand(b.Render(), c);
        }

        public void Clean(SqlConnection c)
        {
            var b = new Accum();
            b.Add("const");
            var cmd = new SqlCommand(b.Render(), c);
        }
    }
}
