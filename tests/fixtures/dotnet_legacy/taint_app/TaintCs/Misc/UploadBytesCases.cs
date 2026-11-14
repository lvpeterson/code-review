using System.IO;
using System.Web;
using System.Web.Mvc;

namespace TaintCs.Misc
{
    // RES-003: saves that go through bytes read from the upload, and size checks on the wrong file.
    public class UploadBytesController : Controller
    {
        private const int MaxBytes = 1048576;

        [HttpPost]
        public ActionResult BinaryReaderWrite(HttpPostedFileBase f)
        {
            var b = new BinaryReader(f.InputStream).ReadBytes(f.ContentLength);
            File.WriteAllBytes("c:\\data\\x.bin", b);
            return Content("ok");
        }

        [HttpPost]
        public ActionResult BufferWrite(HttpPostedFileBase f)
        {
            var buf = new byte[f.ContentLength];
            f.InputStream.Read(buf, 0, buf.Length);
            File.WriteAllBytes("c:\\data\\x.bin", buf);
            return Content("ok");
        }

        [HttpPost]
        public ActionResult BinaryReaderWriteChecked(HttpPostedFileBase f)
        {
            if (f.ContentLength > MaxBytes) { return new HttpStatusCodeResult(413); }
            var b = new BinaryReader(f.InputStream).ReadBytes(f.ContentLength);
            File.WriteAllBytes("c:\\data\\x.bin", b);
            return Content("ok");
        }

        // The check is on a different file than the one saved.
        [HttpPost]
        public ActionResult CheckOnOtherFile(HttpPostedFileBase avatar, HttpPostedFileBase document)
        {
            if (avatar.ContentLength > MaxBytes) { return new HttpStatusCodeResult(413); }
            document.SaveAs("c:\\data\\doc.bin");
            return Content("ok");
        }

        [HttpPost]
        public ActionResult CheckOnSameIndexedFile()
        {
            if (Request.Files[0].ContentLength > MaxBytes) { return new HttpStatusCodeResult(413); }
            Request.Files[0].SaveAs("c:\\data\\a.bin");
            return Content("ok");
        }

        [HttpPost]
        public ActionResult CheckOnWholeRequest(HttpPostedFileBase f)
        {
            if (Request.ContentLength > MaxBytes) { return new HttpStatusCodeResult(413); }
            f.SaveAs("c:\\data\\a.bin");
            return Content("ok");
        }
    }
}
