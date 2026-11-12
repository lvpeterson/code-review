using System.Data.SqlClient;

namespace Cs
{
    public static class Ext
    {
        public static string Join2(this string s, string t)
        {
            return s + t;
        }

        public static void Run2(this string s, string t, SqlConnection c)
        {
            var cmd = new SqlCommand(t, c);
        }

        public static void RunSql(this string s, SqlConnection c)
        {
            var cmd = new SqlCommand(s, c);
        }

        public static void EnumSql(this System.Collections.Generic.IEnumerable<string> e, SqlConnection c)
        {
            var cmd = new SqlCommand(string.Join(",", e), c);
        }

        // Shares its name with a framework method; must never be taken for string.Substring.
        public static string Substring(this string s, int n, bool flag)
        {
            return "const";
        }

        public static void Peek(this Svc h, SqlConnection c)
        {
            var cmd = new SqlCommand(h.Run(), c);
        }
    }
}
