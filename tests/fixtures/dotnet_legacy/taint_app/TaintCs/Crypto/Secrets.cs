using System;
using System.Configuration;
using System.Data.SqlClient;
using System.DirectoryServices;
using System.Net;

namespace TaintCs.Crypto
{
    // Hardcoded credentials in code (SEC-003).
    public class Secrets
    {
        private const string ApiToken = "tok_live_9f8e7d6c5b4a";
        private const string PasswordResetUrl = "https://example.invalid/reset";
        private const string PasswordKey = "Password";
        private const string SecretName = "secret";
        private const string ApiKeyHeader = "ApiKey";
        private const string Token = "token";
        private const string PasswordPrefix = "Password";
        public string DbPassword { get; set; } = "Pr0pSecret!";
        public string AdminPassword = "Sup3rSecret!";

        public NetworkCredential Literal()
        {
            return new NetworkCredential("svc", "hunter2hunter2");
        }

        public NetworkCredential FromConfig()
        {
            return new NetworkCredential("svc", ConfigurationManager.AppSettings["SvcPass"]);
        }

        public DirectoryEntry Ldap()
        {
            return new DirectoryEntry("LDAP://dc.example.invalid", "cn=svc", "Ld4pSecret");
        }

        public SqlConnection Db()
        {
            return new SqlConnection("Server=db.example.invalid;Database=app;User Id=app;Password=Db!Secret99;");
        }

        public SqlConnection DbIntegrated()
        {
            return new SqlConnection("Server=db.example.invalid;Database=app;Integrated Security=true;");
        }

        public SqlConnection DbPlaceholder()
        {
            return new SqlConnection("Server=db.example.invalid;User Id=app;Password={password};");
        }

        public void Locals()
        {
            string clientSecret = "c5e1f0a2-77aa-4d11";
            var pwd = "tmp";
            string adminPassword = "admin";
            string secret = "secret";
            var placeholder = "xxxx";
            string password = "";
            Use(clientSecret, pwd, placeholder, password);
        }

        public void Named()
        {
            Use(password: "N4medSecret");
            Use(passwordFormat: "Clear-Text-Format");
        }

        private void Use(string clientSecret = null, string pwd = null, string placeholder = null, string password = null, string passwordFormat = null)
        {
        }
    }
}
