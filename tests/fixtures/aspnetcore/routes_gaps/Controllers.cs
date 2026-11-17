using Microsoft.AspNetCore.Mvc;

// Third-party base type that is not in the solution: controller semantics assumed.
public class PingEndpoint : EndpointBaseAsync.WithoutRequest.WithActionResult
{
    [HttpGet("api/ping")]
    public override Task<ActionResult> HandleAsync(CancellationToken ct = default) => Task.FromResult<ActionResult>(Ok());
}

[ApiController]
public class StatusEndpoint : VendorEndpointBase
{
    [HttpPost("api/status")]
    public override Task<ActionResult> HandleAsync(CancellationToken ct = default) => Task.FromResult<ActionResult>(Ok());
}

// Plain class with a third-party interface only: not a controller.
public class Helper : IVendorThing
{
    [HttpGet("api/not-a-route")]
    public int Compute() => 1;
}

// Open generic controller types are not routes; a closed derived type is.
[ApiController, Route("api/gen")]
public class GenericBase<T> : ControllerBase
{
    [HttpGet("g")]
    public IActionResult G() => Ok();
}

public class StringController : GenericBase<string> { }

// A route attribute without a verb on a third-party based class: listed, not an API surface by itself.
public class LegacyThing : VendorBase
{
    [Route("old/thing")]
    public IActionResult Old() => Ok();
}
