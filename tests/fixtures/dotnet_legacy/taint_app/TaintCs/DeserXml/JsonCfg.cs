using Newtonsoft.Json;

namespace TaintCs.DeserXml
{
    // Settings held in static fields and used from other types.
    public static class JsonCfg
    {
        public static readonly JsonSerializerSettings Unsafe = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.All
        };

        public static readonly JsonSerializerSettings Safe = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None
        };
    }

    public class JsonUse
    {
        public object ParseUnsafe(string s)
        {
            return JsonConvert.DeserializeObject<object>(s, JsonCfg.Unsafe);
        }

        public object ParseSafe(string s)
        {
            return JsonConvert.DeserializeObject<object>(s, JsonCfg.Safe);
        }

        public object ParseDefault(string s)
        {
            return JsonConvert.DeserializeObject(s);
        }

        public JsonSerializer Serializer()
        {
            return JsonSerializer.Create(JsonCfg.Unsafe);
        }
    }

    // The unsafe value is assigned in a different method than the one that uses it.
    public class LateCfg
    {
        private static JsonSerializerSettings _settings = new JsonSerializerSettings();

        public static void Init()
        {
            _settings.TypeNameHandling = TypeNameHandling.Auto;
        }

        public object Read(string x)
        {
            return JsonConvert.DeserializeObject(x, _settings);
        }
    }

    // A setting that nothing visibly uses: reported at the setting site.
    public class OrphanCfg
    {
        public static JsonSerializerSettings Build()
        {
            var s = new JsonSerializerSettings();
            s.TypeNameHandling = TypeNameHandling.Objects;
            return s;
        }
    }

    public class InlineCfg
    {
        public JsonSerializer Make()
        {
            return new JsonSerializer { TypeNameHandling = TypeNameHandling.Arrays };
        }

        public JsonSerializer MakeNone()
        {
            return new JsonSerializer { TypeNameHandling = TypeNameHandling.None };
        }
    }

    public class Envelope
    {
        [JsonProperty(TypeNameHandling = TypeNameHandling.Auto)]
        public object Payload { get; set; }

        [JsonProperty(TypeNameHandling = TypeNameHandling.None)]
        public object Plain { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }
    }
}
