using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.Mvc;
using System.Web.UI;

namespace TaintCs.DeserXml
{
    public class FormatterController : Controller
    {
        // Request body straight into a BinaryFormatter: proven.
        [AllowAnonymous]
        public ActionResult FromBody()
        {
            var formatter = new BinaryFormatter();
            object o = formatter.Deserialize(Request.InputStream);
            return Content(o.ToString());
        }

        // A file the app wrote itself: the formatter is still dangerous, input not proven.
        [AllowAnonymous]
        public ActionResult FromFile()
        {
            using (var fs = new FileStream(@"C:\data\state.bin", FileMode.Open))
            {
                var o = new BinaryFormatter().Deserialize(fs);
                return Content(o.ToString());
            }
        }

        // NetDataContractSerializer through a field, ViewState-style formatter with a request string.
        private readonly NetDataContractSerializer _ndc = new NetDataContractSerializer();

        [AllowAnonymous]
        public ActionResult Ndc()
        {
            return Content(_ndc.ReadObject(Request.InputStream).ToString());
        }

        [AllowAnonymous]
        public ActionResult ViewStateBlob()
        {
            return Content(new LosFormatter().Deserialize(Request.Form["vs"]).ToString());
        }

        // DataContractSerializer is not on the list.
        public object Contract(Stream s)
        {
            return new DataContractSerializer(typeof(string)).ReadObject(s);
        }
    }
}
