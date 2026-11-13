using System.Xml;

namespace NoTfm
{
    public class Parser
    {
        public string Read(string xml)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xml);
            return doc.InnerText;
        }
    }
}
