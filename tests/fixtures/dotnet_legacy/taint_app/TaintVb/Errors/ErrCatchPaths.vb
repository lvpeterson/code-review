Imports System.Web
Imports System.Web.Mvc
Imports System.Security.Principal

Namespace TaintVb.Errors
    Public Class VbCp
        Inherits Controller

        Private _debug As Boolean

        Public Function B1() As ActionResult
            Try
                If Not User.IsInRole("a") Then Return New HttpUnauthorizedResult()
            Catch ex As Exception
                Response.Redirect("~/Login", endResponse:=False)
            End Try
            Return View()
        End Function

        Public Function A1() As ActionResult
            Try
                If Not User.IsInRole("a") Then Return New HttpUnauthorizedResult()
            Catch ex As Exception
                If _debug Then Response.End()
            End Try
            Return View()
        End Function

        Public Function S1() As ActionResult
            Try
                If Not User.IsInRole("a") Then Return New HttpUnauthorizedResult()
            Catch ex As Exception
                If _debug Then
                    Return New HttpUnauthorizedResult()
                Else
                    Throw
                End If
            End Try
            Return View()
        End Function
    End Class

    Public Class VbCpStatic
        Shared Sub New()
            Try
                Init()
            Catch
            End Try
        End Sub

        Private Shared Sub Init()
        End Sub
    End Class
End Namespace
