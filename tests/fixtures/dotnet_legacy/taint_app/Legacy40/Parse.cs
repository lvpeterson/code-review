using System.Xml;

namespace Legacy40
{
    public class Parser
    {
        // No resolver set on a v4.0 target: the default resolver follows external entities.
        public string Read(string xml)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc.InnerText;
        }

        public string ReadSafe(string xml)
        {
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.LoadXml(xml);
            return doc.InnerText;
        }
    }

    // A null resolver that only arrives after the Load protects nothing.
    public class LateNull
    {
        private readonly XmlDocument _d = new XmlDocument();

        public void Go(string path)
        {
            _d.Load(path);
            _d.XmlResolver = null;
        }
    }

    public class Parser2
    {
        public string Again(string xml)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc.InnerText;
        }
    }
}
