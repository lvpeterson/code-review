using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace CarriedApp.Services;

public class AuditService
{
    private readonly ILogger<AuditService> _logger;

    public AuditService(ILogger<AuditService> logger) { _logger = logger; }

    public void Record(string user, string password, string token)
    {
        _logger.LogInformation($"sign-in for {user} with {password}");
        _logger.LogInformation("token issued: " + token);
        _logger.LogInformation("sign-in for {User}", user);
        _logger.LogInformation("password length {Length}", password.Length);
    }
}

public class SignInService
{
    private readonly ILogger<SignInService> _logger;
    private readonly SignInManager<IdentityUser> _signIn;

    public SignInService(ILogger<SignInService> logger, SignInManager<IdentityUser> signIn)
    {
        _logger = logger;
        _signIn = signIn;
    }

    // No failure branch is ever logged.
    public async Task<bool> Login(string user, string password)
    {
        var result = await _signIn.PasswordSignInAsync(user, password, false, true);
        if (!result.Succeeded)
        {
            return false;
        }
        return true;
    }

    public async Task<bool> LoginAudited(string user, string password)
    {
        var result = await _signIn.PasswordSignInAsync(user, password, false, true);
        if (!result.Succeeded)
        {
            _logger.LogWarning("failed sign-in for {User}", user);
            return false;
        }
        return true;
    }
}
