namespace Cs
{
    public class Svc
    {
        private string _t;

        public Svc(string t)
        {
            _t = t;
        }

        public string Run()
        {
            return _t;
        }
    }
}
