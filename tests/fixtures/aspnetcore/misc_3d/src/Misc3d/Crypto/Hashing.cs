using System.Security.Cryptography;
using System.Text;

namespace Misc3d.Crypto;

public class Hashing
{
    public byte[] Md5Static(byte[] data)
    {
        return MD5.HashData(data);
    }

    public byte[] Sha1Static(string text)
    {
        return SHA1.HashData(Encoding.UTF8.GetBytes(text));
    }

    public async Task<byte[]> Md5Async(Stream s)
    {
        return await MD5.HashDataAsync(s);
    }

    public async Task<byte[]> Sha1Async(Stream s)
    {
        return await SHA1.HashDataAsync(s);
    }

    public byte[] HmacMd5(byte[] key, byte[] data)
    {
        return HMACMD5.HashData(key, data);
    }

    public byte[] Strong(byte[] data)
    {
        return SHA256.HashData(data);
    }
}
