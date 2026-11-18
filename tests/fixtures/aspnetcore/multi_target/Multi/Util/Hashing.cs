using System.Security.Cryptography;

namespace Multi.Util
{
    public static class Hashing
    {
        public static byte[] Digest(byte[] data)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(data);
        }
    }
}
