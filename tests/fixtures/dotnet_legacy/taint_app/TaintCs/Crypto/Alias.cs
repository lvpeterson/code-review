using Sha = System.Security.Cryptography.SHA1;
using Managed = System.Security.Cryptography.SHA1Managed;
using Hash = System.Security.Cryptography.HashAlgorithm;

namespace TaintCs.Crypto
{
    // Weak hashes reached through using-aliases (CRY-001 follows the resolved type).
    public class AliasHashes
    {
        public object AliasSha()
        {
            return Sha.Create();
        }

        public object AliasNew()
        {
            return new Managed();
        }

        public object AliasFactory()
        {
            return Hash.Create("MD5");
        }
    }
}
