Imports System.Security.Principal

Namespace TaintVb.Errors
    ' Statements that share a line with the Try.
    Public Class VbRf
        Public Function X3(ByVal u As IPrincipal) As Boolean
            Try : X3 = u.IsInRole("a") : Catch : End Try : X3 = True
        End Function

        Public Function X4(ByVal u As IPrincipal) As Boolean
            X4 = True : Try : X4 = u.IsInRole("a") : Catch : End Try
        End Function

        Public Function X5(ByVal u As IPrincipal) As Boolean
            Try : X5 = u.IsInRole("a") : Catch : End Try : X5 = False
        End Function
    End Class
End Namespace
