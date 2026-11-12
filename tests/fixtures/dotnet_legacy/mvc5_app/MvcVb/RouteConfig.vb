Imports System.Web.Mvc
Imports System.Web.Routing

Namespace MvcVb
    Public Class RouteConfig
        Public Shared Sub RegisterRoutes(routes As RouteCollection)
            routes.maproute("VbDefault", "vb/{controller}/{action}")
        End Sub
    End Class
End Namespace
