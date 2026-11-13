using System.Web.Script.Serialization;

namespace TaintCs.DeserXml
{
    public class JsSerializers
    {
        public object WithResolver(string s)
        {
            var js = new JavaScriptSerializer(new SimpleTypeResolver());
            return js.DeserializeObject(s);
        }

        public object Plain(string s)
        {
            return new JavaScriptSerializer().DeserializeObject(s);
        }
    }
}
