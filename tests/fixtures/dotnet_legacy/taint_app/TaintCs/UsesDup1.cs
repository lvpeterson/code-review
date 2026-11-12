namespace Cs.Ns1
{
    public class UsesDup1
    {
        public void M()
        {
            var d = new Dup();
            d.Term = System.Web.HttpContext.Current.Request.QueryString["q"];
        }
    }
}
