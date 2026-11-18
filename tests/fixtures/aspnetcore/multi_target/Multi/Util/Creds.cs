using System.Net;

namespace Multi.Util
{
    public static class Creds
    {
        public static NetworkCredential Service() => new NetworkCredential("svc", "ServiceAccountPassword");
    }
}
