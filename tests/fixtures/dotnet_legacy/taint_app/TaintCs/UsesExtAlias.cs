using System.Data.SqlClient;
using U = Cs;

namespace Cs.Alias
{
    public class UsesExtAlias
    {
        public void Static(SqlConnection c)
        {
            string q = System.Web.HttpContext.Current.Request.QueryString["q"];
            U.Ext.RunSql(q, c);
        }
    }
}
