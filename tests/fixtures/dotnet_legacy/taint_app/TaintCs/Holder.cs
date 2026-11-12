namespace Cs
{
    // The setter stores into a field that Read returns.
    public class Holder
    {
        private string _v;

        public string V
        {
            set { _v = value; }
        }

        public string Read()
        {
            return _v;
        }
    }
}
