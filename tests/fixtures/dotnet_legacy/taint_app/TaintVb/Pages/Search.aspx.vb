Namespace Vb.Pages
    Partial Public Class SearchPage
        Inherits System.Web.UI.Page

        Private _term As String

        Protected Sub Page_Load(sender As Object, e As EventArgs) Handles Me.Load
            _term = txtName.Text
        End Sub

        Protected Sub btnGo_Click(sender As Object, e As EventArgs) Handles btnGo.Click
            Dim cmd As New SqlCommand("select * from t where n = '" & _term & "'", New SqlConnection())
        End Sub
    End Class
End Namespace
