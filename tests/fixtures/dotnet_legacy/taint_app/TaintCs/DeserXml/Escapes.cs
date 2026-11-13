using System.IO;
using System.Net.Http.Formatting;
using System.Web.Http;
using System.Web.Mvc;
using System.Xml;
using Newtonsoft.Json;

namespace TaintCs.DeserXml
{
    // Web API formatter settings are reached through a member chain no holder tracking can resolve.
    public static class WebApiJson
    {
        public static void Register(HttpConfiguration config)
        {
            GlobalConfiguration.Configuration.Formatters.JsonFormatter.SerializerSettings.TypeNameHandling = TypeNameHandling.Auto;
            config.Formatters.JsonFormatter.SerializerSettings.TypeNameHandling = TypeNameHandling.Objects;
        }

        public static void RegisterSafe(HttpConfiguration config)
        {
            config.Formatters.JsonFormatter.SerializerSettings.TypeNameHandling = TypeNameHandling.None;
        }

        public static object Wrap()
        {
            return new Holder { TypeNameHandling = TypeNameHandling.All };
        }
    }

    public class Holder
    {
        public TypeNameHandling TypeNameHandling { get; set; }
    }

    // Values that are not the literal TypeNameHandling.X spelling.
    public static class TnhValues
    {
        public static JsonSerializerSettings Num()
        {
            var s = new JsonSerializerSettings();
            s.TypeNameHandling = (TypeNameHandling)4;
            return s;
        }

        public static JsonSerializerSettings Lit()
        {
            var s = new JsonSerializerSettings();
            s.TypeNameHandling = 4;
            return s;
        }

        public static JsonSerializerSettings FromVar(TypeNameHandling mode)
        {
            var s = new JsonSerializerSettings();
            s.TypeNameHandling = mode;
            return s;
        }

        public static JsonSerializerSettings ViaNoneLocal()
        {
            var none = TypeNameHandling.None;
            var s = new JsonSerializerSettings();
            s.TypeNameHandling = none;
            return s;
        }

        public static void Odd(JsonMediaTypeFormatter f)
        {
            f.TypeNameHandling = 4;
        }
    }

    // An unrelated member that happens to be called TypeNameHandling.
    public class Knob
    {
        public int TypeNameHandling { get; set; }

        public static Knob Turn()
        {
            var k = new Knob();
            k.TypeNameHandling = 3;
            return new Knob { TypeNameHandling = 2 };
        }
    }

    // Documents and settings that leave the method that configures them.
    public class XmlEscapes
    {
        public string Caller(string x)
        {
            var d = new XmlDocument();
            d.XmlResolver = new XmlUrlResolver();
            return Do(d, x);
        }

        private string Do(XmlDocument d, string x)
        {
            d.LoadXml(x);
            return d.InnerText;
        }

        public string SafeCaller(string x)
        {
            var d = new XmlDocument();
            d.XmlResolver = null;
            return DoSafe(d, x);
        }

        private string DoSafe(XmlDocument d, string x)
        {
            d.LoadXml(x);
            return d.InnerText;
        }

        // The state is read at the call: set before, nulled after.
        public string SetThenCall(string x)
        {
            var d = new XmlDocument();
            d.XmlResolver = new XmlUrlResolver();
            var r = DoA(d, x);
            d.XmlResolver = null;
            return r;
        }

        private string DoA(XmlDocument d, string x)
        {
            d.LoadXml(x);
            return d.InnerText;
        }

        // Nulled before the call, set only afterwards.
        public string NullThenCall(string x)
        {
            var d = new XmlDocument();
            d.XmlResolver = null;
            var r = DoB(d, x);
            d.XmlResolver = new XmlUrlResolver();
            return r;
        }

        private string DoB(XmlDocument d, string x)
        {
            d.LoadXml(x);
            return d.InnerText;
        }

        public XmlDocument NullAfterSet()
        {
            var d = new XmlDocument();
            d.XmlResolver = new XmlUrlResolver();
            d.XmlResolver = null;
            return d;
        }

        public string Named(string x)
        {
            var d = new XmlDocument { XmlResolver = new XmlUrlResolver() };
            return DoNamed(x: x, d: d);
        }

        private string DoNamed(XmlDocument d, string x)
        {
            d.LoadXml(x);
            return d.InnerText;
        }

        private const DtdProcessing Tight = DtdProcessing.Prohibit;

        public XmlReader ConstMode(Stream s)
        {
            var st = new XmlReaderSettings { DtdProcessing = Tight };
            return XmlReader.Create(s, st);
        }

        public XmlReader Reassigned(Stream s)
        {
            var m = DtdProcessing.Prohibit;
            m = DtdProcessing.Parse;
            var st = new XmlReaderSettings { DtdProcessing = m };
            return XmlReader.Create(s, st);
        }

        private DtdProcessing _fm = DtdProcessing.Prohibit;

        public void SetMode()
        {
            _fm = DtdProcessing.Parse;
        }

        public XmlReader FieldMode(Stream s)
        {
            var st = new XmlReaderSettings { DtdProcessing = _fm };
            return XmlReader.Create(s, st);
        }

        public XmlDocument CondNull(bool safe)
        {
            var d = new XmlDocument();
            d.XmlResolver = new XmlUrlResolver();
            if (safe)
            {
                d.XmlResolver = null;
            }
            return d;
        }

        public string CondCaller(bool safe, string x)
        {
            var d = new XmlDocument();
            d.XmlResolver = new XmlUrlResolver();
            if (safe)
            {
                d.XmlResolver = null;
            }
            return DoC(d, x);
        }

        private string DoC(XmlDocument d, string x)
        {
            d.LoadXml(x);
            return d.InnerText;
        }

        public string Twice(string x)
        {
            var d = new XmlDocument();
            d.XmlResolver = new XmlUrlResolver();
            var a = DoE1(d, x);
            d.XmlResolver = null;
            d.XmlResolver = new XmlUrlResolver();
            return a + DoE2(d, x);
        }

        private string DoE1(XmlDocument d, string x)
        {
            d.LoadXml(x);
            return d.InnerText;
        }

        private string DoE2(XmlDocument d, string x)
        {
            d.LoadXml(x);
            return d.InnerText;
        }

        public XmlReader Make(Stream s)
        {
            var st = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            return Open(s, st);
        }

        private XmlReader Open(Stream s, XmlReaderSettings st)
        {
            return XmlReader.Create(s, st);
        }

        public XmlReader Mode(Stream s, DtdProcessing mode)
        {
            var st = new XmlReaderSettings { DtdProcessing = mode };
            return XmlReader.Create(s, st);
        }
    }

    public class XmlFactoryController : Controller
    {
        private XmlDocument Mk()
        {
            var d = new XmlDocument();
            d.XmlResolver = new XmlUrlResolver();
            return d;
        }

        private XmlDocument MkSafe()
        {
            var d = new XmlDocument();
            d.XmlResolver = null;
            return d;
        }

        [AllowAnonymous]
        public ActionResult ViaFactory()
        {
            var d = Mk();
            d.LoadXml(Request.Form["x"]);
            return Content(d.InnerText);
        }

        [AllowAnonymous]
        public ActionResult ViaDirect()
        {
            Mk().LoadXml(Request.Form["z"]);
            return Content("ok");
        }

        [AllowAnonymous]
        public ActionResult ViaSafeFactory()
        {
            var d = MkSafe();
            d.LoadXml(Request.Form["y"]);
            return Content(d.InnerText);
        }
    }
}
