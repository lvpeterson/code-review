using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationModels;

public class ApiPrefixConvention : IApplicationModelConvention
{
    private readonly AttributeRouteModel _prefix;

    public ApiPrefixConvention(string prefix)
    {
        _prefix = new AttributeRouteModel(new RouteAttribute(prefix));
    }

    public void Apply(ApplicationModel application)
    {
        foreach (var controller in application.Controllers)
        {
            foreach (var selector in controller.Selectors)
            {
                selector.AttributeRouteModel = selector.AttributeRouteModel != null
                    ? AttributeRouteModel.CombineAttributeRouteModel(_prefix, selector.AttributeRouteModel)
                    : _prefix;
            }
        }
    }
}

[ApiController, Route("items")]
public class ItemsController : ControllerBase
{
    [HttpGet("list")]
    public IActionResult List() => Ok();

    [HttpGet("~/rooted")]
    public IActionResult Rooted() => Ok();
}
