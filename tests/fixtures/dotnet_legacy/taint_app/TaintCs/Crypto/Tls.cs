using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace TaintCs.Crypto
{
    public class TrustAll : ICertificatePolicy
    {
        public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem)
        {
            return true;
        }
    }

    public class TrustChecked : ICertificatePolicy
    {
        public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem)
        {
            return problem == 0;
        }
    }

    // Certificate validation (CRY-006) and protocol versions (CRY-007).
    public class TlsSetup
    {
        public void AcceptAnything()
        {
            ServicePointManager.ServerCertificateValidationCallback += (s, cert, chain, errors) => true;
        }

        public void AcceptBlock()
        {
            ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, errors) =>
            {
                return true;
            };
        }

        public void AcceptMethodGroup()
        {
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(AlwaysOk);
        }

        public void AcceptCast()
        {
            ServicePointManager.ServerCertificateValidationCallback = (RemoteCertificateValidationCallback)delegate { return true; };
        }

        public void AcceptPolicy()
        {
            ServicePointManager.CertificatePolicy = new TrustAll();
        }

        public void CheckChain()
        {
            ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, errors) => errors == SslPolicyErrors.None;
        }

        public void CheckMethodGroup()
        {
            ServicePointManager.ServerCertificateValidationCallback = RealCheck;
        }

        public void CheckPolicy()
        {
            ServicePointManager.CertificatePolicy = new TrustChecked();
        }

        public void OldProtocols()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11;
        }

        public void OldSsl()
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Ssl3;
        }

        public void ModernProtocol()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        public void DropSsl()
        {
            ServicePointManager.SecurityProtocol &= ~SecurityProtocolType.Ssl3;
        }

        private static bool AlwaysOk(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        private static bool RealCheck(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
        {
            return errors == SslPolicyErrors.None;
        }
    }
}
