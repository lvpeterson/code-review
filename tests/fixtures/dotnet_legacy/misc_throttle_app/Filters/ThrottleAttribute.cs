using System.Web.Mvc;

namespace Throttled
{
    public class ThrottleAttribute : ActionFilterAttribute
    {
        private readonly int _max;

        public ThrottleAttribute(int max) { _max = max; }

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            var key = filterContext.HttpContext.Request.UserHostAddress;
            if (Hits.Count(key) > _max)
            {
                filterContext.Result = new HttpStatusCodeResult(429);
            }
        }
    }

    public static class Hits
    {
        public static int Count(string key) { return 0; }
    }
}
