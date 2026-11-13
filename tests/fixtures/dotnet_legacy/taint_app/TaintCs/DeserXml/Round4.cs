using System.IO;
using System.Xml;
using Newtonsoft.Json;

namespace TaintCs.DeserXml
{
    public static class Flags
    {
        public static DtdProcessing Ignore = DtdProcessing.Parse;
    }

    public class Round4
    {
        private XmlReaderSettings fst = new XmlReaderSettings();
        private XmlDocument fdoc = new XmlDocument();

        public static JsonSerializerSettings NoneNamed()
        {
            var none = TypeNameHandling.All;
            var s = new JsonSerializerSettings();
            s.TypeNameHandling = none;
            return s;
        }

        public static void NoneNamedStray(System.Web.Http.HttpConfiguration cfg)
        {
            var none = TypeNameHandling.All;
            cfg.Formatters.JsonFormatter.SerializerSettings.TypeNameHandling = none;
        }

        public XmlReader LoopCreate(Stream s, bool c)
        {
            var st = new XmlReaderSettings();
            XmlReader r = null;
            while (c)
            {
                r = XmlReader.Create(s, st);
                st.DtdProcessing = DtdProcessing.Parse;
            }
            return r;
        }

        public XmlReader LoopSafe(Stream s, bool c)
        {
            var st = new XmlReaderSettings();
            XmlReader r = null;
            while (c)
            {
                r = XmlReader.Create(s, st);
                st.DtdProcessing = DtdProcessing.Prohibit;
            }
            return r;
        }

        public XmlDocument SwitchNull(int m)
        {
            var d = new XmlDocument();
            d.XmlResolver = new XmlUrlResolver();
            switch (m)
            {
                case 1:
                    d.XmlResolver = null;
                    break;
            }
            return d;
        }

        public void InitFst()
        {
            fst.DtdProcessing = DtdProcessing.Parse;
        }

        public void HardenFst(bool c)
        {
            if (c)
            {
                fst.DtdProcessing = DtdProcessing.Prohibit;
            }
        }

        public XmlReader OpenFst(Stream s)
        {
            return XmlReader.Create(s, fst);
        }

        public XmlReader ForeignIgnore(Stream s)
        {
            var st = new XmlReaderSettings();
            st.DtdProcessing = Flags.Ignore;
            return XmlReader.Create(s, st);
        }
    }
}
