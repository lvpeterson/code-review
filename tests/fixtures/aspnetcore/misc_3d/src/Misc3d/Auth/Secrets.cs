using System.Net;

namespace Misc3d.Auth;

public static class Names
{
    public const string AccessToken = "accessToken";
    public const string UserToken = "user_token";
    public const string AntiforgeryToken = "__RequestVerificationToken";
    public const string IdToken = "id_token";
    public const string SigningSecret = "Zk3$9vQ!mT7xLp2#Rw8e";
}

public static class WeakLooking
{
    public const string Password = "SuperSecret";
    public const string AdminPassword = "ChangeMe";
    public const string DbPassword = "admin-password";
    public const string ApiPassword = "my_secret_password";
    public const string PasswordPrompt = "Enter your password to continue";
    public const string ClientSecret = "client_id_token";
    public const string LongToken = "the_access_token_name_that_goes_on_and_on_forever_x";

    public static NetworkCredential Build()
    {
        return new NetworkCredential("u", "correct horse battery");
    }
}
