using System.Data.SqlClient;

namespace Cs.Layered
{
    public interface IWriter
    {
        void Save(string v, SqlConnection c);
    }
}
