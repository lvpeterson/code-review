Public Class BasePage
    Inherits System.Web.UI.Page

    Protected Overrides Sub OnPreInit(e As EventArgs)
        MyBase.OnPreInit(e)
        Page.Theme = "Default"
    End Sub
End Class
