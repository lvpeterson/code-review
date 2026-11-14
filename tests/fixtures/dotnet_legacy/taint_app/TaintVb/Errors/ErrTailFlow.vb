Imports System.Security.Principal

Namespace TaintVb.Errors
    ' VB function-name results after a swallowed catch.
    Public Class VbTf
        Public Function X3(ByVal u As IPrincipal) As Boolean
            Try
                X3 = u.IsInRole("a")
            Catch ex As Exception
            End Try
            X3 = True
        End Function

        Public Function W1(ByVal u As IPrincipal) As Boolean
            Try
                Dim r As Boolean = u.IsInRole("a")
            Catch ex As Exception
            End Try
            W1 = True
            Exit Function
        End Function

        Public Function W2(ByVal u As IPrincipal) As Boolean
            Try
                Dim r As Boolean = u.IsInRole("a")
            Catch ex As Exception
            End Try
            Exit Function
        End Function

        Public Function W3(ByVal u As IPrincipal) As Boolean
            W3 = True
            Try
                W3 = u.IsInRole("a")
            Catch ex As Exception
            End Try
        End Function
    End Class
End Namespace
