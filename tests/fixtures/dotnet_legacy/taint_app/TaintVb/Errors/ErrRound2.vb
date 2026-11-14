Imports System.Security.Principal

Namespace TaintVb.Errors
    Public Class VbR2
        Public Property Allowed As Boolean

        Public Function V1(ByVal u As IPrincipal, ByVal flag As Boolean) As Boolean
            Dim allowed As Boolean = False
            If flag Then allowed = True
            Try
                allowed = u.IsInRole("a")
            Catch ex As Exception
                Return allowed
            End Try
            Return allowed
        End Function

        Public Function V2(ByVal u As IPrincipal) As Boolean
            Try
                Me.Allowed = u.IsInRole("a")
            Catch ex As Exception
                Me.Allowed = True
            End Try
            Return Me.Allowed
        End Function
    End Class
End Namespace
