using System.Data.SqlClient;

namespace Cs.Forms
{
    public class UsesExtForms
    {
        public string Ext { get; set; }

        private string GetS() { return "s"; }

        public void PropertyNamedLikeClass(SqlConnection c)
        {
            string q = System.Web.HttpContext.Current.Request.QueryString["q"];
            Ext.Run2(q, c);
        }

        public void UnknownHead(SqlConnection c)
        {
            string q = System.Web.HttpContext.Current.Request.QueryString["q"];
            Mystery.Ext.Run2(q, c);
        }

        public void CallReceiver(SqlConnection c)
        {
            string q = System.Web.HttpContext.Current.Request.QueryString["q"];
            GetS().Run2(q, c);
        }
    }
}
