namespace Sofisoft.Accounts.Identity.API.Application.Adapters
{
    public class UserRegisterDto
    {
        public string UserName { get; set; }
        public string Alias { get; set; }
        public bool LockoutEnabled { get; set; }
        public string Password { get; set; }
        public bool PasswordExpiresEnabled { get; set; }
        
    }
}