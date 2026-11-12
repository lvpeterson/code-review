namespace Cs
{
    public class Linq : System.Web.UI.Page
    {
        // `Users` is not a resolved type here, like a member inherited from an unreferenced base.
        public void DynamicConcat()
        {
            string q = Request.QueryString["q"];
            Users.Where("Name == '" + q + "'");
        }

        public void StaticForm()
        {
            string q = Request.QueryString["q"];
            System.Linq.Dynamic.DynamicQueryable.Where(Users, "Name == '" + q + "'");
        }

        public void DynamicParameterized()
        {
            string q = Request.QueryString["q"];
            Users.Where("Name == @0", q);
        }
    }
}
