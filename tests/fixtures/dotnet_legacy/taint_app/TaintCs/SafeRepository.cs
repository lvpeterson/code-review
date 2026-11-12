using System.Data.SqlClient;

namespace Cs.Layered
{
    public class SafeRepository
    {
        // Constant CommandText + a bound parameter: never a finding.
        public void Find(string term)
        {
            var cmd = new SqlCommand("select * from orders where name = @t", new SqlConnection());
            cmd.Parameters.AddWithValue("@t", term);
        }
    }
}
