using System.Data.SqlClient;

namespace Cs.Layered
{
    public static class Misc
    {
        // Nothing in the solution calls this.
        public static void Orphan(string s, SqlConnection c)
        {
            var cmd = new SqlCommand("select " + s, c);
        }

        public static void OnlyConstCaller(string s, SqlConnection c)
        {
            var cmd = new SqlCommand("select " + s, c);
        }

        public static void CallsConst(SqlConnection c)
        {
            OnlyConstCaller("abc", c);
        }
    }
}
