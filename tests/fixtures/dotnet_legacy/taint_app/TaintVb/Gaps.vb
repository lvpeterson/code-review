Namespace Vb
    Public Class Gaps
        Inherits System.Web.UI.Page

        ' VB dictionary-access (bang) syntax lowers to an unknown node.
        Public Sub Bang(conn As SqlConnection)
            Dim q As String = Request.QueryString!q
            Dim cmd As New SqlCommand(q, conn)
        End Sub

        Public Sub BangConst(conn As SqlConnection)
            Dim q As String = "a"
            Dim cmd As New SqlCommand(q, conn)
        End Sub
    End Class
End Namespace
