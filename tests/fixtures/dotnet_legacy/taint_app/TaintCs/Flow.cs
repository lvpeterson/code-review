using System.Collections.Generic;
using System.Data.SqlClient;

namespace Cs
{
    // Propagation through helpers the table lists explicitly or by the tainted-receiver default.
    public class Flow : System.Web.UI.Page
    {
        public void SplitFirst(SqlConnection c)
        {
            var parts = Request.QueryString["q"].Split(',');
            var cmd = new SqlCommand(parts[0], c);
        }

        public void ListJoin(SqlConnection c)
        {
            var list = new List<string>();
            list.Add(Request.QueryString["q"]);
            var joined = string.Join(",", list);
            var cmd = new SqlCommand("select * from t where n in (" + joined + ")", c);
        }

        public void UnknownReceiverMethod(SqlConnection c)
        {
            string s = Request.QueryString["q"];
            string t = s.SomethingUnknown();
            var cmd = new SqlCommand(t, c);
        }

        public void MutatorOnProjectType(SqlConnection c)
        {
            var b = new Builder();
            var r = b.Add(Request.QueryString["q"]);
            var cmd = new SqlCommand(r, c);
        }

        public void NamedArgument(SqlConnection c)
        {
            var cmd = new SqlCommand(cmdText: Request.QueryString["q"], connection: c);
        }

        public void BoolMemberIsNotData(SqlConnection c)
        {
            string s = Request.QueryString["q"];
            var cmd = new SqlCommand(s.StartsWith("a") ? "select 1" : "select 2", c);
        }

        public void ParameterizedStaysClean(SqlConnection c)
        {
            var cmd = new SqlCommand("select * from t where n = @n", c);
            cmd.Parameters.Add("@n", Request.QueryString["q"]);
            var ad = new SqlDataAdapter(cmd);
        }
    }
}
