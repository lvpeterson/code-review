using System.Web.Http;
using System.Web.Mvc;

namespace TaintCs.Misc
{
    // INV-002: Swagger and test / debug controllers.
    public static class SwaggerConfig
    {
        public static void Register()
        {
            GlobalConfiguration.Configuration
                .EnableSwagger(c => c.SingleApiVersion("v1", "Orders API"))
                .EnableSwaggerUi();
        }
    }

    public class DebugController : Controller
    {
        public ActionResult Index() { return Content("debug"); }
    }

    public class OrdersTestController : ApiController
    {
        public IHttpActionResult Get() { return Ok(); }
    }

    public class DiagnosticsController : ApiController
    {
        public IHttpActionResult Get() { return Ok(); }
    }

    // Names that only contain the letters: not test / debug endpoints.
    public class LatestController : Controller
    {
        public ActionResult Index() { return Content("latest"); }
    }

    public class TestimonialController : Controller
    {
        public ActionResult Index() { return Content("testimonials"); }
    }
}
