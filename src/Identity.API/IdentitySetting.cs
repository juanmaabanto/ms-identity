namespace Sofisoft.Accounts.Identity.API
{
    public class IdentitySetting
    {
        public string ReturnUrl { get; set; }
        public ServicesSetting Services { get; set; }
    }

    public class ServicesSetting
    {
        public string LoggingUrl { get; set; }
    }
}