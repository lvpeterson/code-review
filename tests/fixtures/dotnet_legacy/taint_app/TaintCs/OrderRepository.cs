using System.Data.SqlClient;

namespace Cs.Layered
{
    public class OrderRepository
    {
        public string FindByTerm(string term)
        {
            string t = Cs.Helpers.Wrap(term);
            var cmd = new SqlCommand("select * from orders where name = '" + t + "'", new SqlConnection());
            return "";
        }
    }
}
