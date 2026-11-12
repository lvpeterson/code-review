using System.Data.SqlClient;

namespace Cs
{
    // A ten-deep helper chain with the sink at the bottom.
    public static class Chain
    {
        public static void H0(string s, SqlConnection c)
        {
            H1(s, c);
        }

        public static void H1(string s, SqlConnection c)
        {
            H2(s, c);
        }

        public static void H2(string s, SqlConnection c)
        {
            H3(s, c);
        }

        public static void H3(string s, SqlConnection c)
        {
            H4(s, c);
        }

        public static void H4(string s, SqlConnection c)
        {
            H5(s, c);
        }

        public static void H5(string s, SqlConnection c)
        {
            H6(s, c);
        }

        public static void H6(string s, SqlConnection c)
        {
            H7(s, c);
        }

        public static void H7(string s, SqlConnection c)
        {
            H8(s, c);
        }

        public static void H8(string s, SqlConnection c)
        {
            H9(s, c);
        }

        public static void H9(string s, SqlConnection c)
        {
            var cmd = new SqlCommand(s, c);
        }
    }
}
