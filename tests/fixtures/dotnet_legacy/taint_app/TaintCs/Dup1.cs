using System.Data.SqlClient;

namespace Cs.Ns1
{
    public class Dup
    {
        public string Term
        {
            set { var cmd = new SqlCommand(value, new SqlConnection()); }
        }
    }
}
