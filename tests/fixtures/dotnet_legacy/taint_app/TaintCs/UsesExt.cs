using System.Data.SqlClient;

namespace Cs
{
    public class UsesExt
    {
        public void Sink(SqlConnection c)
        {
            string q = System.Web.HttpContext.Current.Request.QueryString["q"];
            q.RunSql(c);
        }

        public void Ret(SqlConnection c)
        {
            string q = System.Web.HttpContext.Current.Request.QueryString["q"];
            var x = q.Join2("a");
            var cmd = new SqlCommand(x, c);
        }

        public void ConstReceiver(SqlConnection c)
        {
            string q = "const";
            q.RunSql(c);
            var cmd = new SqlCommand(q.Join2("b"), c);
        }

        public void VarNamedLikeClass(SqlConnection c)
        {
            string Ext = System.Web.HttpContext.Current.Request.QueryString["q"];
            Ext.RunSql(c);
        }

        public void WrongType(SqlConnection c)
        {
            var l = new System.Collections.Generic.List<string>();
            l.Add(System.Web.HttpContext.Current.Request.QueryString["q"]);
            l.RunSql(c);
        }

        public void LostArgument(SqlConnection c)
        {
            var x = "c".Join2("a", System.Web.HttpContext.Current.Request.QueryString["q"]);
            var cmd = new SqlCommand(x, c);
        }

        public void FrameworkSupertype(SqlConnection c)
        {
            var l = new System.Collections.Generic.List<string>();
            l.Add(System.Web.HttpContext.Current.Request.QueryString["q"]);
            l.EnumSql(c);
        }

        public void ExternalSameName(SqlConnection c)
        {
            string q = System.Web.HttpContext.Current.Request.QueryString["q"];
            var x = q.Substring(1);
            var cmd = new SqlCommand(x, c);
        }

        public void UnrelatedProjectType(SqlConnection c)
        {
            var h = new Holder();
            h.V = System.Web.HttpContext.Current.Request.QueryString["q"];
            h.Peek(c);
        }
    }
}
