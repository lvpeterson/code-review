using System.Data.SqlClient;

namespace Cs.Layered
{
    public static class Shared
    {
        public static void Run(string s)
        {
            var cmd = new SqlCommand("select " + s, new SqlConnection());
        }
    }
}
