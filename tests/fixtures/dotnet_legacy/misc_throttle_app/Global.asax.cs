using System.Web;
using System.Web.Mvc;

namespace Throttled
{
    public class MvcApplication : HttpApplication
    {
        protected void Application_Start()
        {
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
        }
    }
}
