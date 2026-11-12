Namespace Vb
    Partial Public Class Search
        Inherits System.Web.UI.Page

        ' Mixed-case names: VB variables are case-insensitive.
        Public Sub Go(conn As SqlConnection)
            Dim Sql = "select * from t where n = '"
            sql &= txtName.Text
            Dim cmd As New SqlCommand(SQL, conn)
        End Sub

        ' VB module string functions called without a receiver.
        Public Sub Funcs(conn As SqlConnection)
            Dim q As String = Trim(Mid(Request.QueryString("q"), 2))
            Dim cmd As New SqlCommand(q, conn)
        End Sub

        ' Default-property forms of the request object.
        Public Sub DefaultProp(conn As SqlConnection)
            Dim a As String = Request("q")
            Dim cmd As New SqlCommand(a, conn)
        End Sub

        ' A local collection that shares a name with a VB string function.
        Public Sub LocalNamedLeft(conn As SqlConnection)
            Dim left As System.Collections.Specialized.NameValueCollection = Request.QueryString
            Dim cmd As New SqlCommand(left("q"), conn)
        End Sub

        Public Sub QsCall(conn As SqlConnection)
            Dim cmd As New SqlCommand(Request.QueryString("q"), conn)
        End Sub
    End Class
End Namespace
