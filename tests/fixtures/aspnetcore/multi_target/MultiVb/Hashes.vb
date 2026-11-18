Imports System.Security.Cryptography

Namespace MultiVb
    Public Class Hashes
        Public Shared Function Digest(data As Byte()) As Byte()
            Dim md5 As MD5 = MD5.Create()
            Return md5.ComputeHash(data)
        End Function
    End Class
End Namespace
