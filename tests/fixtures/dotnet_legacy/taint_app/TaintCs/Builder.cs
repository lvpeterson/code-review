namespace Cs
{
    // A project type whose Add is a plain string function, not a collection mutator.
    public class Builder
    {
        public string Add(string s)
        {
            return "x" + s;
        }
    }
}
