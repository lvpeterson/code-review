Imports System.Web.Mvc

Namespace TaintVb.Errors
    ' VB: identifiers are case-insensitive, so EX / Ex / ex are one catch variable.
    Public Class VbErrController
        Inherits Controller

        Public Function Leak() As ActionResult
            Try
                Work()
            Catch ex As Exception
                Dim m As String = "Failed: " & EX.Message
                Return Content(m)
            End Try
            Return Content("ok")
        End Function

        Public Function LeakBag() As ActionResult
            Try
                Work()
            Catch ex As Exception
                ViewBag.Error = ex.InnerException.Message
            End Try
            Return View()
        End Function

        Public Function Generic() As ActionResult
            Try
                Work()
            Catch ex As Exception
                System.Diagnostics.Trace.TraceError(ex.ToString())
                Return Content("Something went wrong")
            End Try
            Return Content("ok")
        End Function

        Public Function Swallow() As ActionResult
            Try
                Work()
            Catch
            End Try
            Return Content("ok")
        End Function

        Public Function SwallowTyped() As ActionResult
            Try
                Work()
            Catch ex As System.Exception
            End Try
            Return Content("ok")
        End Function

        Private Sub Work()
        End Sub
    End Class

    Public Class VbAuth
        Inherits AuthorizeAttribute

        Protected Overrides Function AuthorizeCore(ByVal httpContext As System.Web.HttpContextBase) As Boolean
            Try
                Return httpContext.User.IsInRole("admin")
            Catch ex As Exception
                Return True
            End Try
        End Function
    End Class

    Public Class VbAuthEmpty
        Inherits AuthorizeAttribute

        Protected Overrides Function AuthorizeCore(ByVal httpContext As System.Web.HttpContextBase) As Boolean
            Try
                If Not httpContext.User.IsInRole("admin") Then Return False
            Catch
            End Try
            Return True
        End Function
    End Class

    Public Class VbAuthSafe
        Inherits AuthorizeAttribute

        Protected Overrides Function AuthorizeCore(ByVal httpContext As System.Web.HttpContextBase) As Boolean
            Try
                Return httpContext.User.IsInRole("admin")
            Catch ex As Exception
                Return False
            End Try
        End Function
    End Class
End Namespace
