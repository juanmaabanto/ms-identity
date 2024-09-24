using System;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Sofisoft.Accounts.Identity.API.Application.Services;
using Sofisoft.Accounts.Identity.API.Infrastructure.Exceptions;
using Sofisoft.Accounts.Identity.API.Infrastructure.Filters;
using Sofisoft.Accounts.Identity.API.ViewModels;

namespace Sofisoft.Accounts.Identity.API.Controllers
{
    public class AuthorizationController : ControllerBase
    {
        #region Variables
        private readonly IUserService _userService;

        #endregion

        #region Constructor

        public AuthorizationController(IUserService userService)
        {
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
        }

        #endregion

        #region Posts

        [Authorize]
        [FormValueRequired("submit.Accept")]
        [HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Accept(CancellationToken cancellationToken)
        {
            try
            {
                var request = HttpContext.GetOpenIddictServerRequest() ??
                    throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

                Int32.TryParse(request.GetParameter("authuser").ToString(), out int  authuser);
                var companyId = request.GetParameter("company_id").ToString();
                var claims = User.Identities.ElementAtOrDefault(authuser) ??
                    throw new IdentityDomainException("No se encontro sesión del usuario.");

                if(!claims.IsAuthenticated)
                {
                    return Unauthorized();
                }

                var userId = claims.FindFirst(ClaimTypes.NameIdentifier).Value;
                var user = await _userService.GetUserByCompanyAsync(userId, companyId);
                string alias = Convert.ToString(user.Alias);
                
                if(user.Company is null)
                {
                    throw new IdentityDomainException("No tiene acceso a la empresa o no tiene asignado una principal.");
                }

                companyId = Convert.ToString(user.Company.CompanyId);

                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, 
                    OpenIddictConstants.Claims.Name, 
                    OpenIddictConstants.Claims.Role);

                identity.AddClaim(OpenIddictConstants.Claims.Subject, userId);

                identity.AddClaim("user_id", userId,
                    OpenIddictConstants.Destinations.AccessToken);

                identity.AddClaim("company_id", companyId,
                    OpenIddictConstants.Destinations.AccessToken);

                identity.AddClaim("cliente_id", request.ClientId.ToString(),
                    OpenIddictConstants.Destinations.AccessToken);

                identity.AddClaim(OpenIddictConstants.Claims.Username, claims.FindFirst(ClaimTypes.Name).Value,
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken);

                identity.AddClaim(OpenIddictConstants.Claims.Name, alias,
                            OpenIddictConstants.Destinations.IdentityToken);

                if(user.ImageUri is not null)
                {
                    string imageUri = Convert.ToString(user.ImageUri);

                    if (Uri.TryCreate(imageUri, UriKind.Absolute, out Uri outUri) && (outUri.Scheme == Uri.UriSchemeHttp || outUri.Scheme == Uri.UriSchemeHttps))
                    {
                        identity.AddClaim(OpenIddictConstants.Claims.Profile, imageUri,
                            OpenIddictConstants.Destinations.IdentityToken);
                    }
                }

                identity.AddClaim(OpenIddictConstants.Claims.Audience, "sofisoft",
                        OpenIddictConstants.Destinations.AccessToken);
                
                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(identity),
                    new AuthenticationProperties(),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                ticket.Principal.SetScopes(new[]
                {
                    /* openid: */ OpenIddictConstants.Scopes.OpenId,
                    /* offline_access: */ OpenIddictConstants.Scopes.OfflineAccess
                }.Intersect(request.GetScopes()));
                
                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }
            catch (IdentityDomainException ex)
            {
                return BadRequest(new ErrorViewModel(ex.ErrorId, ex.Message));
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new ErrorViewModel(ex.Message));
            }
        }

        #endregion
    }
}