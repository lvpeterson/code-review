using System.Web.Mvc;

namespace Throttled
{
    public static class FilterConfig
    {
        // Review Focus 4: the throttle is registered globally, so every sensitive action is covered.
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new ThrottleAttribute(20));
        }
    }
}
