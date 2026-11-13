using System;
using System.Security.Cryptography;
using System.Text;
using System.Web.Security;

namespace TaintCs.Crypto
{
    // Weak hashes (CRY-001): the password context raises the severity.
    public class WeakHashes
    {
        public string HashPassword(string password)
        {
            using (var md5 = MD5.Create())
            {
                return Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
            }
        }

        public string Etag(string body)
        {
            var sha1 = new SHA1Managed();
            return Convert.ToBase64String(sha1.ComputeHash(Encoding.UTF8.GetBytes(body)));
        }

        public string LegacyStore(string pw)
        {
            return FormsAuthentication.HashPasswordForStoringInConfigFile(pw, "MD5");
        }

        public void TwoOnOneLine()
        {
            var a = MD5.Create(); var b = SHA1.Create();
        }

        public string LegacyFine(string pw)
        {
            return FormsAuthentication.HashPasswordForStoringInConfigFile(pw, "SHA256");
        }

        public string StrongHash(string password)
        {
            using (var sha = SHA256.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(password)));
            }
        }
    }
}
