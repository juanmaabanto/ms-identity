using System.Threading.Tasks;
using Sofisoft.Accounts.Identity.API.Application.Adapters;
using Sofisoft.Accounts.Identity.API.Models;

namespace Sofisoft.Accounts.Identity.API.Application.Services
{
    public interface IUserService
    {
        Task<User> AddAsync(UserRegisterDto item);
        Task<User> AuthenticateAsync(string username, string password);
        Task<dynamic> FindByNameAsync(string userName);
        Task<dynamic> GetClientAppUserAsync(string userName, string clientAppId);
        Task<dynamic> GetUserByCompanyAsync(string userId, string companyId);
    }
}