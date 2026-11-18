namespace Misc3d.Services;

public class TruthHost
{
    public bool Pick()
    {
        return Lookup();
    }

    private bool Lookup()
    {
        return true;
    }
}

public class TruthDecoy
{
    public bool Lookup()
    {
        return false;
    }
}
