using System.IO;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;

namespace TaintCs.Misc
{
    public class FileStore
    {
        public void Save(HttpPostedFileBase f)
        {
            f.SaveAs("c:\\data\\" + Path.GetFileName(f.FileName));
        }
    }

    // RES-003: uploads with and without a size check that guards the save.
    public class UploadController : Controller
    {
        private const int MaxBytes = 1048576;
        private readonly FileStore _store = new FileStore();

        [HttpPost]
        public ActionResult Save(HttpPostedFileBase file)
        {
            file.SaveAs("c:\\data\\" + Path.GetFileName(file.FileName));
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveChecked(HttpPostedFileBase file)
        {
            if (file.ContentLength > MaxBytes)
            {
                return new HttpStatusCodeResult(413);
            }
            file.SaveAs("c:\\data\\" + Path.GetFileName(file.FileName));
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveCheckedInside(HttpPostedFileBase file)
        {
            if (file != null && file.ContentLength > 0 && file.ContentLength <= MaxBytes)
            {
                file.SaveAs("c:\\data\\" + Path.GetFileName(file.FileName));
            }
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveElseRejects(HttpPostedFileBase file)
        {
            if (file.ContentLength <= MaxBytes)
            {
                file.SaveAs("c:\\data\\" + Path.GetFileName(file.FileName));
            }
            else
            {
                return new HttpStatusCodeResult(413);
            }
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveViaAlias(HttpPostedFileBase file)
        {
            int len = file.ContentLength;
            if (len > MaxBytes)
            {
                return new HttpStatusCodeResult(413);
            }
            file.SaveAs("c:\\data\\" + Path.GetFileName(file.FileName));
            return Content("ok");
        }

        // Only a lower bound: ContentLength > 0 limits nothing.
        [HttpPost]
        public ActionResult SaveLowerOnly(HttpPostedFileBase file)
        {
            if (file.ContentLength > 0)
            {
                file.SaveAs("c:\\data\\" + Path.GetFileName(file.FileName));
            }
            return Content("ok");
        }

        // The check is there, but a too-big file is still saved.
        [HttpPost]
        public ActionResult SaveCheckDoesNotStop(HttpPostedFileBase file)
        {
            if (file.ContentLength > MaxBytes)
            {
                ModelState.AddModelError("", "too big");
            }
            file.SaveAs("c:\\data\\" + Path.GetFileName(file.FileName));
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveCheckAfter(HttpPostedFileBase file)
        {
            var path = "c:\\data\\" + Path.GetFileName(file.FileName);
            file.SaveAs(path);
            if (file.ContentLength > MaxBytes)
            {
                System.IO.File.Delete(path);
            }
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveFiles()
        {
            foreach (string name in Request.Files)
            {
                var f = Request.Files[name];
                f.SaveAs("c:\\data\\" + Path.GetFileName(f.FileName));
            }
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveFilesChecked()
        {
            foreach (string name in Request.Files)
            {
                var f = Request.Files[name];
                if (f.ContentLength > MaxBytes) { continue; }
                f.SaveAs("c:\\data\\" + Path.GetFileName(f.FileName));
            }
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveCopy(HttpPostedFileBase file)
        {
            using (var fs = System.IO.File.Create("c:\\data\\x.bin"))
            {
                file.InputStream.CopyTo(fs);
            }
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveViaHelper(HttpPostedFileBase file)
        {
            _store.Save(file);
            return Content("ok");
        }

        [HttpPost]
        public ActionResult SaveViaHelperChecked(HttpPostedFileBase file)
        {
            if (file.ContentLength > MaxBytes)
            {
                return new HttpStatusCodeResult(413);
            }
            _store.Save(file);
            return Content("ok");
        }

        // Not an upload at all: SaveAs on something unrelated has no upload in the method.
        public ActionResult NotUpload()
        {
            return Content("ok");
        }
    }

    public class ApiUploadController : ApiController
    {
        public async Task<IHttpActionResult> Post()
        {
            var provider = new MultipartFormDataStreamProvider("c:\\data");
            await Request.Content.ReadAsMultipartAsync(provider);
            return Ok();
        }
    }
}
