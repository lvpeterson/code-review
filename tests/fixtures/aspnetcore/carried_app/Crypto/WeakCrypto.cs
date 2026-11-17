using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace CarriedApp.Crypto;

public class WeakCrypto
{
    private static readonly byte[] FixedKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    public string HashPassword(string password)
    {
        using var md5 = MD5.Create();
        var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToHexString(bytes);
    }

    public byte[] Checksum(byte[] data)
    {
        using var sha = SHA1.Create();
        return sha.ComputeHash(data);
    }

    public ICryptoTransform OldCipher()
    {
        var des = DES.Create();
        return des.CreateEncryptor();
    }

    public byte[] Encrypt(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Key = FixedKey;
        return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
    }

    public string NewToken()
    {
        var rng = new Random();
        var token = rng.Next().ToString();
        return token;
    }

    public byte[] Derive(string password, byte[] salt)
    {
        using var kdf = new Rfc2898DeriveBytes(password, salt, 1000);
        return kdf.GetBytes(32);
    }

    public HttpClientHandler Lax()
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
        return handler;
    }

    public string Connect()
    {
        var adminPassword = "Sup3rS3cret!";
        return adminPassword;
    }
}
