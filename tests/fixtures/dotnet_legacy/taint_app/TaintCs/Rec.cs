using System.Data.SqlClient;

namespace Cs.Layered
{
    // Mutually recursive pair; the sink sits in A.
    public static class Rec
    {
        public static void A(string s, SqlConnection c)
        {
            if (s.Length > 3)
            {
                B(s, c);
            }
            var cmd = new SqlCommand("select " + s, c);
        }

        public static void B(string s, SqlConnection c)
        {
            A(s.Substring(1), c);
        }
    }
}
