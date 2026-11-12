using System.Data.SqlClient;
using System.Linq;

namespace Cs.Objects
{
    // Data access one call away from the action.
    public class OrderLookup
    {
        private readonly ShopContext _db = new ShopContext();

        public Order Load(int orderId)
        {
            return _db.Orders.SingleOrDefault(o => o.Id == orderId);
        }

        public string LoadRaw(int orderId)
        {
            var cmd = new SqlCommand("select * from orders where id = " + orderId, new SqlConnection());
            return "";
        }

        // Takes an id but never touches the data store.
        public string Label(int orderId)
        {
            return "order-" + orderId;
        }

        // Reads the user but never guards the data access.
        public string AuditUser(int orderId)
        {
            return System.Web.HttpContext.Current.User.Identity.Name + orderId;
        }
    }
}
