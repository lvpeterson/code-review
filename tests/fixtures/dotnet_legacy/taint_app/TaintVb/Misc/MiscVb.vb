Imports System.Net.Http
Imports System.Web.Mvc
Imports System.Web.Security
Imports log4net

Namespace TaintVb.Misc
    Public Class VbLoginModel
        Public Property UserName As String
        Public Property Password As String
    End Class

    ' VB: identifiers are case-insensitive (LOG / Log, MEMBERSHIP / Membership).
    Public Class VbMiscController
        Inherits Controller

        Private Shared ReadOnly Log As ILog = LogManager.GetLogger("vb")
        Private Const LegacyUrl As String = "http://vb.example.net/api"

        ' LOG-003: a secret reaches the log, with other casing.
        Public Function LeakPwd(model As VbLoginModel) As ActionResult
            LOG.Info("pwd=" & MODEL.PASSWORD)
            Return Content("x")
        End Function

        Public Function LeakInterp(model As VbLoginModel) As ActionResult
            Dim pw As String = model.Password
            Log.Warn($"login {pw}")
            Return Content("x")
        End Function

        Public Function UserOnly(model As VbLoginModel) As ActionResult
            Log.Info("user " & model.UserName)
            Return Content("x")
        End Function

        ' DES-001: no lockout / protected.
        <HttpPost>
        Public Function Login(model As VbLoginModel) As ActionResult
            Return View(model)
        End Function

        <HttpPost>
        Public Function LoginChecked(model As VbLoginModel) As ActionResult
            If MEMBERSHIP.VALIDATEUSER(model.UserName, model.Password) Then
                Return Redirect("/")
            End If
            Return View(model)
        End Function

        <HttpPost>
        Public Function LoginDebug(model As VbLoginModel, debug As Boolean) As ActionResult
            If debug Then
                Dim ok = Membership.ValidateUser(model.UserName, model.Password)
            End If
            Return View(model)
        End Function

        ' CONSUME-001.
        Public Function Outbound() As Object
            Dim c As New HttpClient()
            Return c.GetStringAsync("http://vb.example.net/x")
        End Function

        Public Function OutboundConst() As Object
            Dim c As New HttpClient()
            Return c.GetStringAsync(LEGACYURL & "/orders")
        End Function

        Public Function OutboundSecure() As Object
            Dim c As New HttpClient()
            Return c.GetStringAsync("https://vb.example.net/x")
        End Function
    End Class
End Namespace
