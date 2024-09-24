using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MongoDB.Bson;
using MongoDB.Driver;
using Sofisoft.Accounts.Identity.API.Application.Adapters;
using Sofisoft.Accounts.Identity.API.Infrastructure.Exceptions;
using Sofisoft.Accounts.Identity.API.Models;
using Sofisoft.Accounts.Identity.API.Utils;
using Sofisoft.Accounts.Identity.API.Application.WebClients;
using Sofisoft.Enterprise.SeedWork.MongoDB.Domain;

namespace Sofisoft.Accounts.Identity.API.Application.Services
{
    public class UserService : IUserService
    {
        private readonly int _maxFailedAccessAttempts = 4;
        private readonly ILoggingWebClient _logger;
        private readonly IRepository<ClientApp> _clientAppRepository;
        private readonly IRepository<User> _userRepository;

        public UserService(IRepository<ClientApp> clientAppRepository,
            IRepository<User> userRepository, ILoggingWebClient logger)
        {
            _clientAppRepository = clientAppRepository ?? throw new ArgumentNullException(nameof(clientAppRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<User> AddAsync(UserRegisterDto item)
        {
            string userName = "test";

            try
            {
                var existent = await _userRepository.FindOneAsync(f => f.UserName == item.UserName);

                if(existent is not null)
                {
                    throw new IdentityDomainException("Ya existe el usuario");
                }
                    
                var user = new User {
                    AccessFailedCount = 0,
                    Active = true,
                    Alias = item.Alias,
                    CreatedBy = userName,
                    LockoutEnabled = item.LockoutEnabled,
                    LockoutEnd = null,
                    NormalizedUserName = item.UserName.ToUpperInvariant(),
                    UserName = item.UserName,
                    PasswordExpiresEnabled = item.PasswordExpiresEnabled,
                    PasswordExpires = item.PasswordExpiresEnabled ? DateTime.UtcNow.AddMonths(3) : null,
                    PasswordHash = PasswordHasher.HashPassword(item.Password),
                    RequestPasswordChange = true,
                    SecurityStamp = Helper.GenerateSecurityStamp()
                };

                await _userRepository.InsertOneAsync(user);

                return user;
            }
            catch(IdentityDomainException)
            {
                throw;
            }
            catch (Exception ex)
            {
                var result = await _logger.ErrorAsync(ex.Message, ex.StackTrace, userName);

                throw new IdentityDomainException("Ocurrio un error al registrar.", result);
            }
        }

        public async Task<User> AuthenticateAsync(string username, string password)
        {
            try
            {
                var normalized = username?.ToUpperInvariant();
                var user = await _userRepository.FindOneAsync(f => f.NormalizedUserName == normalized);

                if(user is null)
                {
                    throw new IdentityDomainException("Usuario o contraseña incorrecta.");
                }

                if(!user.Active)
                {
                    throw new IdentityDomainException("La cuenta del usuario no se encuentra activa.");
                }

                if(user.IsLockedOut())
                {
                    var remaining = (user.LockoutEnd.Value - DateTime.UtcNow).ToString(@"mm\m\ ss\s\ ");

                    throw new IdentityDomainException($"El usuario se encuentra bloqueado. {remaining} restantes");
                }

                var result = PasswordHasher.VerifyHashedPassword(user.PasswordHash, password);

                if(result)
                {
                    user.AccessFailedCount = 0;
                    await _userRepository.UpdateOneAsync(user);

                    return user;
                }
                else
                {
                    var attempts = _maxFailedAccessAttempts - user.AccessFailedCount;

                    if(attempts <= 0)
                    {
                        attempts = _maxFailedAccessAttempts;
                        user.AccessFailedCount = 0;
                    }

                    user.AccessFailedCount += 1;

                    if(user.AccessFailedCount >= _maxFailedAccessAttempts)
                    {
                        user.LockoutEnd = DateTime.UtcNow.AddMinutes(5);
                        await _userRepository.UpdateOneAsync(user);

                        var remaining = (user.LockoutEnd.Value - DateTime.UtcNow).ToString(@"mm\m\ ss\s\ ");

                        throw new IdentityDomainException($"Contraseña incorrecta. Cuenta Bloqueada. {remaining}restantes");
                    }
                    else
                    {
                        await _userRepository.UpdateOneAsync(user);
                        throw new IdentityDomainException($"Contraseña incorrecta. {attempts - 1} intento(s) restante(s).");
                    }
                }
            }
            catch(IdentityDomainException)
            {
                throw;
            }
            catch (Exception ex)
            {
                var result = await _logger.ErrorAsync(ex.Message, ex.StackTrace, username);

                throw new IdentityDomainException("Ocurrio un error al intentar autenticar.", result);
            }
        }
        
        public async Task<dynamic> FindByNameAsync(string userName)
        {
            try
            {
                var normalized = userName?.ToUpperInvariant();
                var user = await _userRepository.FindOneAsync(
                    f => f.NormalizedUserName == normalized,
                    p => new {
                        p.Alias,
                        p.ImageUri,
                        p.UserName
                    }
                );

                if(user is null)
                {
                    throw new KeyNotFoundException("No pudimos encontrar tu cuenta");
                }

                return user;
            }
            catch (KeyNotFoundException)
            {
                throw;
            }
            catch (Exception ex)
            {
                var result = await _logger.ErrorAsync(ex.Message, ex.StackTrace, userName);

                throw new IdentityDomainException("Ocurrio un error obteniendo datos de tu cuenta.", result);
            }
        }

        public async Task<dynamic> GetClientAppUserAsync(string userName, string clientAppId)
        {
            try
            {
                var clientApp = await _clientAppRepository.FindByIdAsync(clientAppId);

                if(clientApp is null)
                {
                    throw new IdentityDomainException("El client_Id no es válido.");
                }

                var normalized = userName?.ToUpperInvariant();
                var userData = await _userRepository.FindOneAsync(
                    f => f.NormalizedUserName == normalized,
                    p => new {
                        p.UserName,
                        ClientApps = p.ClientApps ?? new List<UserClientApp>()
                    }
                );

                if(userData is null)
                {
                    throw new IdentityDomainException("No se encontro el usuario.");
                }
                
                var app = userData.ClientApps
                    .FirstOrDefault(p => p.ClientAppId == clientAppId);

                return new {
                    userName = userData.UserName,
                    clientAppName = clientApp.Name,
                    hasAccess = app != null && app.HasAccess,
                    permitted = (app != null && app.Permitted) || !clientApp.ThirdParty
                };
            }
            catch(IdentityDomainException)
            {
                throw;
            }
            catch (Exception ex)
            {
                var result = await _logger.ErrorAsync(ex.Message, ex.StackTrace, userName);

                throw new IdentityDomainException("Ocurrio un error obteniendo datos.", result);
            }
        }
    
        public async Task<dynamic> GetUserByCompanyAsync(string userId, string companyId)
        {
            try
            {
                var user = await _userRepository.FindOneAsync(
                    f => f.Id == userId,
                    p => new {
                        p.Id,
                        p.UserName,
                        p.Alias,
                        p.ImageUri,
                        Company = string.IsNullOrWhiteSpace(companyId) ?
                            p.Companies.FirstOrDefault(p => p.Principal == true) :
                            p.Companies.FirstOrDefault(p => p.CompanyId == companyId)
                    }
                );

                if(user is null)
                {
                    throw new IdentityDomainException("No se econtro el usuario.");
                }

                return user;
            }
            catch (IdentityDomainException)
            {
                throw;
            }
            catch (Exception ex)
            {
                var result = await _logger.ErrorAsync(ex.Message, ex.StackTrace, string.Empty);

                throw new IdentityDomainException("Ocurrio un error obteniendo datos.", result);
            }
        }
    }
}