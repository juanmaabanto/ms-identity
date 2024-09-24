using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Sofisoft.Accounts.Identity.API.Application.Services;
using Sofisoft.Accounts.Identity.API.Infrastructure.Exceptions;
using Sofisoft.Accounts.Identity.API.ViewModels;

namespace Sofisoft.Accounts.Identity.API.Controllers
{
    public class AccountController : ControllerBase
    {
        #region Variables

        private readonly IDataProtector _protector;
        private readonly IOptions<IdentitySetting> _settings;
        private readonly IUserService _userService;

        #endregion

        #region Constructor

        public AccountController(IDataProtectionProvider protectorProvider, IOptions<IdentitySetting> settings, IUserService userService)
        {
            _protector = protectorProvider.CreateProtector("Sofisoft.Accounts.Identity.API");
            _settings = settings ?? throw new ArgumentNullException(nameof(settings));
            _userService = userService ?? throw new ArgumentNullException(nameof(userService));
        }

        #endregion

        #region Gets

        [Authorize]
        [HttpGet("~/oauth/check")]
        public async Task<IActionResult> Check(string clientId, int authuser)
        {
            var identity = User.Identities.ElementAtOrDefault(authuser)
                ?? (ClaimsIdentity) User.Identity;

            if(!identity.IsAuthenticated)
            {
                return Unauthorized();
            }

            try
            {
                var result = await _userService.GetClientAppUserAsync(identity.Name, clientId);

                return Ok(result);
            }
            catch (IdentityDomainException ex)
            {
                return BadRequest(new ErrorViewModel(ex.ErrorId, ex.Message));
            }
        }

        #endregion

        #region Posts

        [AllowAnonymous]
        [HttpPost("~/signin")]
        public async Task<IActionResult> SignIn(string username, string password, bool isPersistent, string @continue)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return BadRequest(new ErrorViewModel(null, $"The value of the '{nameof(username)}' parameter is null or invalid"));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                return BadRequest(new ErrorViewModel(null, $"The value of the '{nameof(password)}' parameter is null or invalid"));
            }

            try
            {
                var user = await _userService.AuthenticateAsync(username, password);

                if(user.RequestPasswordChange
                    || (user.PasswordExpiresEnabled && user.PasswordExpires.HasValue && user.PasswordExpires.Value < DateTime.UtcNow ) ) 
                {
                    return Ok(new { RequirePasswordChange = true });
                }

                var principal = new ClaimsPrincipal();
                var claims = new List<Claim> { 
                    new Claim(ClaimTypes.Name, user.UserName), 
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim("SecurityStamp", user.SecurityStamp)
                };
                var identity = new ClaimsIdentity(claims, "Sofisoft");
                var accounts = new List<string>();

                if(Request.Cookies["Sofisoft.Accounts"] != null && Request.Cookies["Sofisoft.Accounts"].Length > 0)
                {
                    accounts = _protector.Unprotect(Request.Cookies["Sofisoft.Accounts"]).Split(";").ToList();
                }

                if(!accounts.Contains(user.UserName))
                {
                    accounts.Add(user.UserName);
                }

                var cookieOptions = new CookieOptions();
                cookieOptions.Expires = DateTime.Now.AddDays(365);
                cookieOptions.HttpOnly = true;
                cookieOptions.SameSite = SameSiteMode.None;
                cookieOptions.Secure = true;

                Response.Cookies.Append("Sofisoft.Accounts", _protector.Protect(String.Join(";", accounts)), cookieOptions);

                foreach(var i in User.Identities)
                {
                    if(i.Name != null)
                    {
                        if(i.Name == identity.Name)
                        {
                            principal.AddIdentity(identity);
                        }
                        else
                        {
                            principal.AddIdentity(i);
                        }
                    }
                }

                if(!principal.Identities.Contains(identity))
                {
                    principal.AddIdentity(identity);
                }

                if (!(Uri.TryCreate(@continue, UriKind.Absolute, out Uri outUri) && (outUri.Scheme == Uri.UriSchemeHttp || outUri.Scheme == Uri.UriSchemeHttps)))
                {
                    @continue = _settings.Value.ReturnUrl;
                }

                var uriBuilder = new UriBuilder(@continue);
                var query = HttpUtility.ParseQueryString(uriBuilder.Query);

                uriBuilder.Query = query.ToString();

                if(isPersistent)
                {
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties() { IsPersistent = true });
                }
                else
                {
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                }

                return Ok(new { Url = uriBuilder.Uri.ToString() });
            }
            catch(IdentityDomainException ex)
            {
                return BadRequest(new ErrorViewModel(ex.ErrorId, ex.Message));
            }
            catch (CryptographicException)
            {
                return BadRequest(new ErrorViewModel(null, "Ocurrio un error al leer las Cookies"));
            }
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("~/signin/user/lookup")]
        public async Task<IActionResult> Lookup(string userName)
        {
            try
            {
                var result = await _userService.FindByNameAsync(userName);
                var accounts = new List<string>();

                if(Request.Cookies["Sofisoft.Accounts"] != null && Request.Cookies["Sofisoft.Accounts"].Length > 0)
                {
                    accounts = _protector.Unprotect(Request.Cookies["Sofisoft.Accounts"]).Split(";").ToList();
                }

                if(accounts.Contains(result.UserName))
                {
                    return Ok(result);
                }
                else
                {
                    return Ok(new { UserName = result.UserName });
                }
            }
            catch (IdentityDomainException ex)
            {
                return BadRequest(new ErrorViewModel(ex.ErrorId, ex.Message));
            }
            catch(KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (CryptographicException)
            {
                return BadRequest(new ErrorViewModel(null, "Ocurrio un error al leer las Cookies"));
            }
        }

        [AllowAnonymous]
        [HttpGet("~/signout"), HttpPost("~/signout")]
        public ActionResult SignOutAll()
        {
            return SignOut(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        #endregion
    }
}