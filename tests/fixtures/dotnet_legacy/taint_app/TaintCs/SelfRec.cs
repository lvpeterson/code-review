using System.Data.SqlClient;

namespace Cs
{
    public static class SelfRec
    {
        // Only calls itself.
        public static void Loop(string s, SqlConnection c)
        {
            var cmd = new SqlCommand("select " + s, c);
            if (s.Length > 0) Loop(s.Substring(1), c);
        }
    }
}
