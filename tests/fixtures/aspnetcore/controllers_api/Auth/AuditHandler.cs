using Microsoft.AspNetCore.Authorization;

public class AuditRequirement : IAuthorizationRequirement
{
}

public class AuditHandler : AuthorizationHandler<AuditRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AuditRequirement requirement)
    {
        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
