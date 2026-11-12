namespace Cs.Ns2
{
    public class UsesDup2
    {
        public void M()
        {
            var d = new Dup();
            d.Term = System.Web.HttpContext.Current.Request.QueryString["q"];
        }
    }
}
