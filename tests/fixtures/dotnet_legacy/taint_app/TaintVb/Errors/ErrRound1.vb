Imports System.Security.Principal

Namespace TaintVb.Errors
    Public Class VbR1
        Public Function Fn1(ByVal u As IPrincipal) As Boolean
            Try
                Fn1 = u.IsInRole("a")
            Catch ex As Exception
                Fn1 = True
            End Try
        End Function

        Public Function Fn2(ByVal u As IPrincipal) As Boolean
            Dim ok As Boolean = False
            Try
                ok = u.IsInRole("a")
            Catch ex As Exception
                ok = True
            End Try
            Return ok
        End Function

        Public Function Fn3(ByVal u As IPrincipal) As Boolean
            Dim ok As Boolean = False
            Try
                ok = u.IsInRole("a")
            Catch ex As Exception
                ok = False
            End Try
            Return ok
        End Function

        Public Function Fn4(ByVal u As IPrincipal) As Boolean
            Try
                Fn4 = u.IsInRole("a")
            Catch ex As Exception
                Fn4 = False
            End Try
        End Function
    End Class
End Namespace
