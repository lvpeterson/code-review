using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

// Named like a controller but opted out, so its public method is not an action.
[NonController]
public class NotAController
{
    public void Run() { }
}

// Not a controller by name, base or attribute.
public class PlainService
{
    public void Run() { }
}
