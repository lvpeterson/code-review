using System.ServiceModel;

namespace WcfSvc
{
    [ServiceContract]
    public interface IOrderService
    {
        [OperationContract]
        string Find(string term);

        [OperationContract]
        void Delete(int id);
    }
}
