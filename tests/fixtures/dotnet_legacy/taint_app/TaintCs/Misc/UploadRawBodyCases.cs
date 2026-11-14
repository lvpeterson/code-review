using System.IO;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;

namespace TaintCs.Misc
{
    // RES-003: uploads that arrive as the raw request body, and index-sensitive size checks.
    public class RawBodyUploadController : Controller
    {
        private const int MaxBytes = 1048576;

        [HttpPost]
        public ActionResult RawInputStreamCopy()
        {
            using (var fs = File.Create("c:\\data\\raw.bin"))
            {
                Request.InputStream.CopyTo(fs);
            }
            return Content("ok");
        }

        [HttpPost]
        public ActionResult RawInputStreamCopyChecked()
        {
            if (Request.ContentLength > MaxBytes) { return new HttpStatusCodeResult(413); }
            using (var fs = File.Create("c:\\data\\raw.bin"))
            {
                Request.InputStream.CopyTo(fs);
            }
            return Content("ok");
        }

        [HttpPost]
        public ActionResult RawBinaryReader()
        {
            var b = new BinaryReader(Request.InputStream).ReadBytes(Request.ContentLength);
            File.WriteAllBytes("c:\\data\\raw.bin", b);
            return Content("ok");
        }

        // The check is on file "a", the save is of file "b".
        [HttpPost]
        public ActionResult CheckOnOtherIndex()
        {
            if (Request.Files["a"].ContentLength > MaxBytes) { return new HttpStatusCodeResult(413); }
            Request.Files["b"].SaveAs("c:\\data\\b.bin");
            return Content("ok");
        }

        [HttpPost]
        public ActionResult CheckOnOtherPosition()
        {
            if (Request.Files[0].ContentLength > MaxBytes) { return new HttpStatusCodeResult(413); }
            Request.Files[1].SaveAs("c:\\data\\b.bin");
            return Content("ok");
        }

        [HttpPost]
        public ActionResult CheckOnSameLiteralIndex()
        {
            if (Request.Files["a"].ContentLength > MaxBytes) { return new HttpStatusCodeResult(413); }
            Request.Files["a"].SaveAs("c:\\data\\a.bin");
            return Content("ok");
        }
    }

    public class RawBodyApiController : ApiController
    {
        private const int MaxBytes = 1048576;

        public async Task<IHttpActionResult> PostStream()
        {
            var s = await Request.Content.ReadAsStreamAsync();
            using (var fs = File.Create("c:\\data\\api.bin"))
            {
                await s.CopyToAsync(fs);
            }
            return Ok();
        }

        public async Task<IHttpActionResult> PostBytes()
        {
            File.WriteAllBytes("c:\\data\\api.bin", await Request.Content.ReadAsByteArrayAsync());
            return Ok();
        }

        public async Task<IHttpActionResult> PostBytesChecked()
        {
            if (Request.Content.Headers.ContentLength > MaxBytes) { return BadRequest(); }
            File.WriteAllBytes("c:\\data\\api.bin", await Request.Content.ReadAsByteArrayAsync());
            return Ok();
        }
    }
}
