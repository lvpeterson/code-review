using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TaintCs.Crypto
{
    // Weak algorithms (CRY-002), ECB (CRY-003), constant key / IV (CRY-004).
    public class Ciphers
    {
        public byte[] OldDes(byte[] data)
        {
            var des = new DESCryptoServiceProvider();
            return des.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }

        public byte[] OldTripleDes(byte[] data)
        {
            var t = TripleDES.Create();
            return t.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
        }

        public byte[] EcbAes(byte[] data)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            }
        }

        public byte[] CbcAes(byte[] data)
        {
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.GenerateIV();
                return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            }
        }

        public byte[] ConstantIv(byte[] data)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef");
                aes.IV = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
                return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            }
        }

        public ICryptoTransform ConstantKeyArg(Aes aes)
        {
            return aes.CreateDecryptor(Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw=="), new byte[16]);
        }

        public byte[] RandomIv(byte[] data, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();
                return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);
            }
        }

        // An unrelated object with Key / IV members is not a cipher.
        public void NotACipher(KeyHolder h)
        {
            h.Key = Encoding.UTF8.GetBytes("label-not-a-key");
            h.IV = new byte[] { 1 };
        }
    }

    // Constant forms of key material and the ways a buffer stops being constant.
    public class KeyForms
    {
        private const string ConstKey = "0123456789abcdef";
        private static readonly string StaticKey = "fedcba9876543210";
        private const byte Pad = 7;
        private static readonly byte[] Mixed = new byte[] { (byte)1, Pad, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        public void FilledIv(Aes aes)
        {
            var iv = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }
            aes.IV = iv;
        }

        public void CopiedIv(Aes aes, byte[] src)
        {
            var iv = new byte[16];
            Array.Copy(src, iv, 16);
            aes.IV = iv;
        }

        public void ZeroIv(Aes aes)
        {
            aes.IV = new byte[16];
        }

        public void ZeroIvLocal(Aes aes)
        {
            var iv = new byte[16];
            aes.IV = iv;
        }

        public void ConstString(Aes aes)
        {
            aes.Key = Encoding.UTF8.GetBytes(ConstKey);
        }

        public void StaticString(Aes aes)
        {
            aes.Key = Encoding.UTF8.GetBytes(StaticKey);
        }

        public void LocalString(Aes aes)
        {
            string k = "localkey-0123456";
            aes.Key = Encoding.UTF8.GetBytes(k);
        }

        public void AppendedConst(Aes aes)
        {
            string key = "abc";
            key += "defghijk";
            aes.Key = Encoding.UTF8.GetBytes(key);
        }

        public void SaltedString(Aes aes, string userName)
        {
            string salt = "app";
            salt += userName;
            aes.Key = Encoding.UTF8.GetBytes(salt);
        }

        public void ReassignedString(Aes aes, string userName)
        {
            string salt = "app";
            salt = salt + userName;
            aes.Key = Encoding.UTF8.GetBytes(salt);
        }

        public void ArrayFillZero(Aes aes)
        {
            var iv = new byte[16];
            Array.Fill(iv, (byte)0);
            aes.IV = iv;
        }

        public void ArrayFillRandom(Aes aes, byte b)
        {
            var iv = new byte[16];
            Array.Fill(iv, b);
            aes.IV = iv;
        }

        public void FromParam(Aes aes, string passphrase)
        {
            aes.Key = Encoding.UTF8.GetBytes(passphrase);
        }

        public void MixedIv(Aes aes)
        {
            aes.IV = Mixed;
        }
    }

    // A local of the same name in another method does not touch the constant field.
    public class ShadowFields
    {
        private static readonly byte[] iv = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        public void UseField(Aes aes)
        {
            aes.IV = iv;
        }

        public void Unrelated()
        {
            var iv = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }
        }
    }

    // A field buffer filled by the RNG anywhere in the type is not constant; an unfilled one is.
    public class FieldBuffers
    {
        private byte[] _iv = new byte[16];
        private byte[] _zeroIv = new byte[16];

        public FieldBuffers()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(_iv);
            }
        }

        public void UseFilled(Aes aes)
        {
            aes.IV = _iv;
        }

        public void UseZero(Aes aes)
        {
            aes.IV = _zeroIv;
        }
    }

    // Property initializers are scanned like field initializers.
    public class PropInit
    {
        public SymmetricAlgorithm Engine { get; } = new AesManaged { Key = Encoding.UTF8.GetBytes("0123456789abcdef") };
        private static byte[] FixedKey { get; } = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        public void Use(Aes aes)
        {
            aes.Key = FixedKey;
        }
    }

    public class KeyHolder
    {
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }
    }

    // Object state across methods: the cipher lives in a field, its settings are made elsewhere.
    public class StatefulCipher
    {
        private static readonly byte[] FixedIv = new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6 };
        private readonly Aes _aes = Aes.Create();
        private SymmetricAlgorithm Engine { get; set; }

        public StatefulCipher()
        {
            _aes.Mode = CipherMode.ECB;
            Engine = new AesManaged();
        }

        public void Setup()
        {
            _aes.IV = FixedIv;
        }

        public void SetupEngine(byte[] key)
        {
            Engine.Key = key;
            Engine.IV = Encoding.ASCII.GetBytes("static-iv-value!");
        }
    }

    public class StatefulSafe
    {
        private readonly Aes _aes = Aes.Create();

        public StatefulSafe(byte[] key)
        {
            _aes.Mode = CipherMode.CBC;
            _aes.Key = key;
        }

        public void Fresh()
        {
            _aes.GenerateIV();
        }
    }
}
