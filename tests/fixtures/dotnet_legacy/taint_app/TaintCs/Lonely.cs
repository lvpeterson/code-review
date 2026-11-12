using System.Data.SqlClient;

namespace Cs
{
    // A setter with a sink that nothing assigns.
    public class Lonely
    {
        public string T
        {
            set { var cmd = new SqlCommand(value, new SqlConnection()); }
        }
    }
}
