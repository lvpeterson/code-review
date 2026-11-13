using System.ServiceModel;

namespace WcfSvc
{
    [ServiceContract]
    public interface IBillingService
    {
        [OperationContract]
        void Charge(string account, int cents);
    }
}
