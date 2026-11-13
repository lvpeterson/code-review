using System.Data.SqlClient;
using System.Security.Permissions;

namespace WcfSvc
{
    public class OrderService : IOrderService
    {
        public string Find(string term)
        {
            var cmd = new SqlCommand("select * from orders where name = '" + term + "'", new SqlConnection());
            return "";
        }

        [PrincipalPermission(SecurityAction.Demand, Role = "Admin")]
        public void Delete(int id)
        {
        }
    }
}
