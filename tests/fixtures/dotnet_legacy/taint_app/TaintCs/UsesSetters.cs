using System.Data.SqlClient;

namespace Cs
{
    public class UsesSetters
    {
        public void Assign()
        {
            var s = new SetSink();
            s.Term = System.Web.HttpContext.Current.Request.QueryString["q"];
        }

        public void AssignConst()
        {
            var s = new SetSink();
            s.Term = "abc";
        }

        public void Init()
        {
            var s = new SetSink { Term = System.Web.HttpContext.Current.Request.QueryString["q"] };
        }

        public void Stored(SqlConnection c)
        {
            var h = new Holder();
            h.V = System.Web.HttpContext.Current.Request.QueryString["q"];
            var cmd = new SqlCommand(h.Read(), c);
        }

        public void StoredConst(SqlConnection c)
        {
            var h = new Holder();
            h.V = "abc";
            var cmd = new SqlCommand(h.Read(), c);
        }

        public void Ctor(SqlConnection c)
        {
            var s = new Svc(System.Web.HttpContext.Current.Request.QueryString["q"]);
            var cmd = new SqlCommand(s.Run(), c);
        }
    }
}
