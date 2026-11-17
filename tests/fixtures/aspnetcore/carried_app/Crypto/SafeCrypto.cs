using System.Security.Cryptography;
using System.Text;

namespace CarriedApp.Crypto;

public class SafeCrypto
{
    public byte[] Digest(byte[] data) => SHA256.HashData(data);

    public byte[] Token()
    {
        var buffer = new byte[32];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    public byte[] Seal(byte[] key, byte[] nonce, byte[] data)
    {
        var cipher = new byte[data.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, data, cipher, tag);
        return cipher;
    }

    public byte[] Stretch(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, 600000, HashAlgorithmName.SHA256, 32);
    }
}
