using System.Data.SqlClient;
using System.Text;

namespace Cs
{
    // One query-building style per method; each must propagate request data.
    public class Props : System.Web.UI.Page
    {
        public void ViaFormat(SqlConnection c)
        {
            string q = Request.Form["name"];
            var cmd = new SqlCommand(string.Format("select * from t where n = '{0}'", q), c);
        }

        public void ViaBuilder(SqlConnection c)
        {
            var sb = new StringBuilder("select * from t where n = '");
            sb.Append(Request.Form["name"]);
            sb.Append("'");
            var cmd = new SqlCommand(sb.ToString(), c);
        }

        public void ViaInterp(SqlConnection c)
        {
            string q = Request.Params["name"];
            var cmd = new SqlCommand($"select * from t where n = '{q}'", c);
        }

        public void ViaPlusEquals(SqlConnection c)
        {
            string sql = "select * from t where n = '";
            sql += Request.Params["name"];
            sql += "'";
            var cmd = new SqlCommand(sql, c);
        }
    }
}
