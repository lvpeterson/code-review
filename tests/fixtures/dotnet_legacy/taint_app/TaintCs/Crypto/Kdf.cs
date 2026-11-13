using System;
using System.Security.Cryptography;

namespace TaintCs.Crypto
{
    // Key derivation (CRY-008).
    public class Kdf
    {
        private const int Iterations = 100000;

        public byte[] Default(string pw, byte[] salt)
        {
            return new Rfc2898DeriveBytes(pw, salt).GetBytes(32);
        }

        public byte[] Few(string pw, byte[] salt)
        {
            return new Rfc2898DeriveBytes(pw, salt, 2000).GetBytes(32);
        }

        public byte[] Many(string pw, byte[] salt)
        {
            return new Rfc2898DeriveBytes(pw, salt, 100000).GetBytes(32);
        }

        public byte[] ManyViaConst(string pw, byte[] salt)
        {
            return new Rfc2898DeriveBytes(pw, salt, Iterations).GetBytes(32);
        }

        public byte[] Old(string pw, byte[] salt)
        {
            return new PasswordDeriveBytes(pw, salt).GetBytes(32);
        }
    }
}
