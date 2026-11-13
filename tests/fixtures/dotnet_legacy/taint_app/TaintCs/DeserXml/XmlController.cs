using System.IO;
using System.Web.Mvc;
using System.Xml;
using System.Xml.XPath;
using System.Xml.Linq;

namespace TaintCs.DeserXml
{
    public class XmlController : Controller
    {
        // Resolver switched on and the document comes from the request: proven.
        [AllowAnonymous]
        public ActionResult ResolverOn()
        {
            var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
            doc.LoadXml(Request.Form["x"]);
            return Content(doc.InnerText);
        }

        // Same shape with the resolver switched off.
        [AllowAnonymous]
        public ActionResult ResolverOff()
        {
            var doc = new XmlDocument { XmlResolver = null };
            doc.LoadXml(Request.Form["y"]);
            return Content(doc.InnerText);
        }

        // Default resolver on a modern target framework: safe.
        [AllowAnonymous]
        public ActionResult ModernDefault()
        {
            var doc = new XmlDocument();
            doc.LoadXml(Request.Form["z"]);
            return Content(doc.InnerText);
        }

        // Resolver assigned after construction.
        [AllowAnonymous]
        public ActionResult ResolverLate()
        {
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            doc.Load(Request.QueryString["u"]);
            return Content(doc.InnerText);
        }

        [AllowAnonymous]
        public ActionResult ParseSettings()
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            using (var r = XmlReader.Create(Request.InputStream, settings))
            {
                var d = new XmlDocument();
                d.Load(r);
                return Content(d.InnerText);
            }
        }

        [AllowAnonymous]
        public ActionResult ProhibitSettings()
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
            using (var r = XmlReader.Create(Request.InputStream, settings))
            {
                var d = new XmlDocument();
                d.Load(r);
                return Content(d.InnerText);
            }
        }

        [AllowAnonymous]
        public ActionResult ParseButNoResolver()
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null };
            using (var r = XmlReader.Create(Request.InputStream, settings))
            {
                return Content(XDocument.Load(r).ToString());
            }
        }

        // Parse + reading a file the app owns: configuration finding only.
        public string Config()
        {
            var settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
            using (var r = XmlReader.Create(@"C:\data\cfg.xml", settings))
            {
                return XDocument.Load(r).ToString();
            }
        }

        [AllowAnonymous]
        public ActionResult TextReaderOpen()
        {
            using (var r = new XmlTextReader(Request.InputStream))
            {
                var d = new XmlDocument();
                d.Load(r);
                return Content(d.InnerText);
            }
        }

        [AllowAnonymous]
        public ActionResult TextReaderClosed()
        {
            using (var r = new XmlTextReader(Request.InputStream) { DtdProcessing = DtdProcessing.Prohibit })
            {
                var d = new XmlDocument();
                d.Load(r);
                return Content(d.InnerText);
            }
        }

        public string TextReaderLegacyFlag(Stream s)
        {
            var r = new XmlTextReader(s);
            r.ProhibitDtd = true;
            return r.ReadString();
        }

        public string TextReaderPlain(Stream s)
        {
            var r = new XmlTextReader(s);
            return r.ReadString();
        }

        // XPathDocument over a Parse reader and over a plain file path.
        public object Xpath(string path)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            return new XPathDocument(XmlReader.Create(path, settings));
        }

        public object XpathPlain()
        {
            return new XPathDocument(@"C:\data\plain.xml");
        }
    }

    // Resolver state tracked across methods of one type.
    public class XmlHolder
    {
        private readonly XmlDocument _loose = new XmlDocument();
        private readonly XmlDocument _tight = new XmlDocument();

        public XmlHolder()
        {
            _loose.XmlResolver = new XmlUrlResolver();
            _tight.XmlResolver = null;
        }

        public void LoadLoose(string path)
        {
            _loose.Load(path);
        }

        public void LoadTight(string path)
        {
            _tight.Load(path);
        }
    }
}
