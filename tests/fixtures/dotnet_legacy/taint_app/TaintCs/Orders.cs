using System.Data.SqlClient;

namespace Cs
{
    public class Orders : System.Web.UI.Page
    {
        public void Find(SqlConnection conn)
        {
            var cmd = new SqlCommand();
            cmd.Connection = conn;
            cmd.CommandText = "select * from orders where name = '" + Request.QueryString["q"] + "'";
        }

        public void ByIntId(SqlConnection conn)
        {
            int id = int.Parse(Request.QueryString["id"]);
            var cmd = new SqlCommand("select * from orders where id = " + id, conn);
        }

        public void Constant(SqlConnection conn)
        {
            var cmd = new SqlCommand("select 1 from orders", conn);
        }
    }
}
