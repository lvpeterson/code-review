using System.Data.SqlClient;

namespace Cs.Layered
{
    // A2 <-> B2 with a sink in B2, entered from C2 (which passes a constant).
    public static class CycleOuter
    {
        public static void A2(string s, SqlConnection c)
        {
            B2(s, c);
        }

        public static void B2(string s, SqlConnection c)
        {
            var cmd = new SqlCommand("select " + s, c);
            if (s.Length > 5) A2(s.Substring(1), c);
        }

        public static void C2(SqlConnection c)
        {
            A2("const", c);
        }
    }
}
