using System.Data.SqlClient;

namespace Cs.Layered
{
    public class SqlImplA : IWriter
    {
        public void Save(string v, SqlConnection c)
        {
            var cmd = new SqlCommand("insert into a values ('" + v + "')", c);
        }
    }
}
