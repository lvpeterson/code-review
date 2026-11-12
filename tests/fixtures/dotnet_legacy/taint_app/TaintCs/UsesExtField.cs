using System.Data.SqlClient;

namespace Cs
{
    public class UsesExtField
    {
        private string Ext;

        public void Dotted(SqlConnection c)
        {
            this.Ext = System.Web.HttpContext.Current.Request.QueryString["q"];
            this.Ext.RunSql(c);
        }
    }
}
