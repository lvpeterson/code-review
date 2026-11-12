namespace Props
{
    // Synthetic model: one auto property and one with explicit accessor bodies.
    public class Holder
    {
        private string _q;
        public string Auto { get; set; }
        public string Q
        {
            get { return _q; }
            set { _q = value; }
        }
    }
}
