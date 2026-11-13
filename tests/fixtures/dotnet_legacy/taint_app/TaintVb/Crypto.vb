Imports System.Security.Cryptography
Imports System.Text

Namespace TaintVb.Crypto
    Public Class VbHashes
        Public Function HashPassword(ByVal password As String) As String
            Dim md5 As MD5 = MD5.Create()
            Return Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password)))
        End Function

        Public Function StrongHash(ByVal password As String) As String
            Dim sha As SHA256 = SHA256.Create()
            Return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(password)))
        End Function

        Public Function EcbVb(ByVal data As Byte()) As Byte()
            Dim aes As Aes = Aes.Create()
            aes.Mode = CIPHERMODE.ecb
            Return aes.CreateEncryptor().TransformFinalBlock(data, 0, data.Length)
        End Function

        Public Property VbPassword As String = "VbPropSecret"

        Private Shared Function VbOk(ByVal s As Object, ByVal c As System.Security.Cryptography.X509Certificates.X509Certificate, ByVal ch As System.Security.Cryptography.X509Certificates.X509Chain, ByVal e As System.Net.Security.SslPolicyErrors) As Boolean
            Return True
        End Function

        Private Shared Function VbReal(ByVal s As Object, ByVal c As System.Security.Cryptography.X509Certificates.X509Certificate, ByVal ch As System.Security.Cryptography.X509Certificates.X509Chain, ByVal e As System.Net.Security.SslPolicyErrors) As Boolean
            Return e = System.Net.Security.SslPolicyErrors.None
        End Function

        Public Sub VbMethodGroup()
            System.Net.ServicePointManager.ServerCertificateValidationCallback = New System.Net.Security.RemoteCertificateValidationCallback(AddressOf VbOk)
        End Sub

        Public Sub VbCheckGroup()
            System.Net.ServicePointManager.ServerCertificateValidationCallback = New System.Net.Security.RemoteCertificateValidationCallback(AddressOf VbReal)
        End Sub

        Public Sub VbTrust()
            System.Net.ServicePointManager.ServerCertificateValidationCallback = Function(s, c, ch, e) True
        End Sub

        Public Sub VbSecret()
            Dim cred = New System.Net.NetworkCredential("svc", "VbS3cretValue")
        End Sub
    End Class
End Namespace
