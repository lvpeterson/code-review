namespace Cs
{
    public class UsesDup
    {
        public void Qualified()
        {
            var d = new Cs.Ns2.Dup();
            d.Term = System.Web.HttpContext.Current.Request.QueryString["q"];
        }

        public void QualifiedInit()
        {
            var d = new Cs.Ns2.Dup { Term = System.Web.HttpContext.Current.Request.QueryString["q"] };
        }

        public void Other()
        {
            var d = new Cs.Ns1.Dup();
            d.Term = System.Web.HttpContext.Current.Request.QueryString["q"];
        }
    }
}
