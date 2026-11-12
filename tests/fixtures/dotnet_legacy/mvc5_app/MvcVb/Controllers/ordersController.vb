Imports System.Web.Mvc

Namespace MvcVb.Controllers
    Public Class ordersController
        Inherits Controller

        Function Index() As ActionResult
            Return View()
        End Function

        Private Function Secret() As ActionResult
            Return View()
        End Function

        <AcceptVerbs(HttpVerbs.Get Or HttpVerbs.Post)>
        Public Function Both() As ActionResult
            Return View()
        End Function
    End Class
End Namespace
