using System.Data.SqlClient;

namespace Cs
{
    // The setter itself reaches a sink.
    public class SetSink
    {
        public string Term
        {
            set { var cmd = new SqlCommand(value, new SqlConnection()); }
        }
    }
}
