<%= Request.QueryString["q"] %>
<%: Request.QueryString["q"] %>
<%# Eval("Name") %>
<%= Server.HtmlEncode(Request.QueryString["q"]) %>
<%@ Page Language="C#" CodeBehind="Show.aspx.cs" Inherits="Web.ShowPage" %>
