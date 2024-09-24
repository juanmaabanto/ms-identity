using System;
using System.Threading.Tasks;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Sofisoft.Accounts.Identity.API.Models;
using Sofisoft.Enterprise.SeedWork.MongoDB.Domain;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Sofisoft.Accounts.Identity.API.Providers
{
    public class AuthorizationValidator : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>
    {
        private readonly IRepository<ClientApp> _clientAppRepository;
        
        public AuthorizationValidator(IRepository<ClientApp> clientAppRepository)
        {
            _clientAppRepository = clientAppRepository ?? 
                throw new ArgumentNullException(nameof(clientAppRepository));
        }

        public async ValueTask HandleAsync(ValidateAuthorizationRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.Request.IsImplicitFlow())
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.UnsupportedResponseType,
                    description: "Este servidor de autorización solo admite el flujo implícito.");

                return;
            }
            
            if (!string.IsNullOrEmpty(context.Request.ResponseMode) && !context.Request.IsFormPostResponseMode() &&
                                                                       !context.Request.IsFragmentResponseMode() &&
                                                                       !context.Request.IsQueryResponseMode())
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "El especificado 'response_mode' no es soportado.");

                return;
            }

            var clientApp = await _clientAppRepository.FindByIdAsync(context.ClientId);

            if (clientApp == null)
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "El identificador de cliente especificado no es válido.");

                return;
            }

            if (string.IsNullOrEmpty(context.RedirectUri) || 
                !string.Equals(context.RedirectUri, clientApp.RedirectUri, StringComparison.Ordinal))
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "El especificado 'redirect_uri' no es válido.");
                return;
            }

            context.SetRedirectUri(clientApp.RedirectUri);
        }
    }
}