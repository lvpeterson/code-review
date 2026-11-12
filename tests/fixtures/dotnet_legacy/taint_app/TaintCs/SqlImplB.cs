using System.Data.SqlClient;

namespace Cs.Layered
{
    public class SqlImplB : IWriter
    {
        public void Save(string v, SqlConnection c)
        {
            var cmd = new SqlCommand("insert into b values ('" + v + "')", c);
        }
    }
}
