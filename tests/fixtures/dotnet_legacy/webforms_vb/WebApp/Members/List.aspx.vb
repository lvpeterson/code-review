Imports System.Web.Security

Public Class ListPage
    Inherits BasePage

    Protected Sub Page_Load(sender As Object, e As EventArgs) Handles Me.Load
        If Not User.Identity.IsAuthenticated Then FormsAuthentication.RedirectToLoginPage()
    End Sub
End Class
