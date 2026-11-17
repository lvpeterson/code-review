using System.Text.Json;
using System.Xml;
using Newtonsoft.Json;

namespace CarriedApp.Deser;

public class SafeDeser
{
    public Item? ReadText(string json) => System.Text.Json.JsonSerializer.Deserialize<Item>(json);

    public object? ReadJson(string json)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
        return JsonConvert.DeserializeObject(json, settings);
    }

    public XmlReader Open(Stream input)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
        return XmlReader.Create(input, settings);
    }

    public string Parse(string xml)
    {
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        return doc.InnerText;
    }
}

public class Item
{
    public string Name { get; set; } = "";
}
