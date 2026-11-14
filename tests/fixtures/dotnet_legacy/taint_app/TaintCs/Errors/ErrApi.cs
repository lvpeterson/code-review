using System;
using System.ServiceModel;
using System.Web.Http;

namespace TaintCs.Errors
{
    public class ErrApiController : ApiController
    {
        public IHttpActionResult Get(int id)
        {
            try { Work(); }
            catch (Exception ex)
            {
                return InternalServerError(ex);
            }
            return Ok();
        }

        public IHttpActionResult Post(int id)
        {
            try { Work(); }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
            return Ok();
        }

        public IHttpActionResult Put(int id)
        {
            try { Work(); }
            catch (Exception ex)
            {
                throw new HttpResponseException(Request.CreateErrorResponse(System.Net.HttpStatusCode.InternalServerError, ex.Message));
            }
            return Ok();
        }

        public IHttpActionResult Delete(int id)
        {
            try { Work(); }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError(ex.ToString());
                return InternalServerError();
            }
            return Ok();
        }

        private void Work() { }
    }

    [ServiceContract]
    public interface IErrSvc
    {
        [OperationContract]
        string Run(string arg);

        [OperationContract]
        string RunSafe(string arg);
    }

    public class ErrSvc : IErrSvc
    {
        public string Run(string arg)
        {
            try { return arg.ToUpper(); }
            catch (Exception ex)
            {
                throw new FaultException(ex.Message);
            }
        }

        public string RunSafe(string arg)
        {
            try { return arg.ToUpper(); }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError(ex.ToString());
                throw new FaultException("Request failed");
            }
        }
    }
}
