using System.Runtime.Serialization.Formatters.Binary;
using System.Web.Script.Serialization;
using System.Xml;
using Newtonsoft.Json;

namespace CarriedApp.Deser;

public class UnsafeDeser
{
    public object ReadBinary(Stream input)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(input);
    }

    public object ReadJson(string json)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        return JsonConvert.DeserializeObject(json, settings);
    }

    public object ReadScript(string json)
    {
        var serializer = new JavaScriptSerializer(new SimpleTypeResolver());
        return serializer.DeserializeObject(json);
    }

    public string Parse(string xml)
    {
        var doc = new XmlDocument();
        doc.XmlResolver = new XmlUrlResolver();
        doc.LoadXml(xml);
        return doc.InnerText;
    }

    public XmlReader Open(Stream input)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
        return XmlReader.Create(input, settings);
    }
}
