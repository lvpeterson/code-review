using System;
using System.Security.Cryptography;
using System.Text;

namespace TaintCs.Crypto
{
    // System.Random feeding secrets (CRY-005).
    public class Tokens
    {
        private readonly Random _rnd = new Random();

        public string ResetToken()
        {
            var r = new Random();
            return r.Next(100000, 999999).ToString();
        }

        public string MakeCode()
        {
            var sb = new StringBuilder();
            for (int i = 0; i < 8; i++)
            {
                sb.Append(_rnd.Next(0, 9));
            }
            return sb.ToString();
        }

        public byte[] Fill()
        {
            var salt = new byte[16];
            new Random().NextBytes(salt);
            return salt;
        }

        public int Shuffle()
        {
            return _rnd.Next(10);
        }

        public string SecureToken()
        {
            var buf = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(buf);
            }
            return Convert.ToBase64String(buf);
        }
    }
}
