namespace Cs
{
    // Stores its argument in a field; Render returns the field.
    public class Accum
    {
        private string _buf = "";

        public void Add(string s)
        {
            _buf = _buf + s;
        }

        public string Render()
        {
            return _buf;
        }
    }
}
