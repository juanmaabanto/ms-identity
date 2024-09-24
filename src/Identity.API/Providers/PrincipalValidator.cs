using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using Sofisoft.Accounts.Identity.API.Models;
using Sofisoft.Enterprise.SeedWork.MongoDB.Domain;

namespace Sofisoft.Accounts.Identity.API.Providers
{
    public static class PrincipalValidator
    {
        public static Task RedirectAsync(RedirectContext<CookieAuthenticationOptions> context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Response.StatusCode = (int) HttpStatusCode.Unauthorized;
            return Task.CompletedTask;
        }

        public static async Task ValidateAsync(CookieValidatePrincipalContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if(context.Request.Path.Value == "/oauth/check")
            {
                var query = HttpUtility.ParseQueryString(context.Request.QueryString.Value);
                Int32.TryParse(query["authuser"], out int authuser);
                var myIdentity = context.Principal.Identities.ElementAtOrDefault(authuser);

                if(myIdentity is null || !myIdentity.IsAuthenticated)
                {
                    context.RejectPrincipal();
                    return;
                }

                var stamp = myIdentity.Claims.FirstOrDefault(claim => claim.Type == "SecurityStamp")?.Value;
                var userId = myIdentity.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.NameIdentifier)?.Value;

                if(userId is null)
                {
                    context.RejectPrincipal();
                    return;
                }

                var repository = context.HttpContext.RequestServices.GetRequiredService<IRepository<User>>();
                var user = await repository.FindOneAsync(
                    f => f.Id == userId,
                    p => new { p.Id, p.SecurityStamp, p.UserName });

                if(user is null || stamp is null || user.SecurityStamp != stamp)
                {
                    var principal = new ClaimsPrincipal();

                    foreach (var identity in context.Principal.Identities)
                    {
                        if(identity.Claims.FirstOrDefault(
                            claim => claim.Type == ClaimTypes.NameIdentifier)?.Value == user.Id)
                        {
                            var claims = new List<Claim> { 
                                new Claim(ClaimTypes.Name, user.UserName), 
                                new Claim(ClaimTypes.NameIdentifier, user.Id),
                                new Claim("SecurityStamp", user.SecurityStamp)
                            };
                            
                            principal.AddIdentity(new ClaimsIdentity(claims));
                        }
                        else
                        {
                            principal.AddIdentity(identity);
                        }
                    }

                    context.ReplacePrincipal(principal);
                    context.ShouldRenew = true;
                    context.Response.StatusCode = (int) HttpStatusCode.Unauthorized;
                    return;
                }
            }
        }
    }
}