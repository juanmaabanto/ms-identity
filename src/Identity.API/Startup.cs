using System;
using System.Security.Cryptography.X509Certificates;
using Autofac;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Sofisoft.Accounts.Identity.API.Infrastructure.AutofacModules;
using Sofisoft.Accounts.Identity.API.Providers;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Sofisoft.Accounts.Identity.API
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        private readonly IWebHostEnvironment _env;

        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            Configuration = configuration;
            _env = env;
        }
        
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<IdentitySetting>(Configuration);

            if(_env.IsDevelopment())
            {
                services.AddDataProtection()
                    .UseEphemeralDataProtectionProvider();
            }
            else
            {
                services.AddDataProtection()
                    .PersistKeysToAzureBlobStorage(new Uri(Configuration["BlobSasUri"]))
                    .ProtectKeysWithCertificate(new X509Certificate2(
                        Configuration["Kestrel:Certificates:Default:Path"],
                        Configuration["Kestrel:Certificates:Default:Password"])
                    );
            }

            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
            });

            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy",
                    builder => builder.WithOrigins(Configuration["AllowedOrigins"].Split(";"))
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials());
            });

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.Name = "Sofisoft.Identity";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.None;
                options.Cookie.SecurePolicy = _env.IsDevelopment() ? CookieSecurePolicy.None : CookieSecurePolicy.Always;
                options.ExpireTimeSpan = TimeSpan.FromDays(365);
                options.SlidingExpiration = true;
                options.Events.OnRedirectToLogin = PrincipalValidator.RedirectAsync;
                options.Events.OnValidatePrincipal = PrincipalValidator.ValidateAsync;
            });

            services.AddOpenIddict()
            .AddCore(options => {
            })
            .AddServer(options => {
                //endpoints
                options.SetAuthorizationEndpointUris("/connect/authorize");
                //scopes
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OfflineAccess);
                //flujos
                options.AllowImplicitFlow();
                //
                options.AcceptAnonymousClients();
                options.EnableDegradedMode();

                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(10));
                //security
                if(_env.IsDevelopment())
                {
                    options.AddEphemeralEncryptionKey();
                    options.AddEphemeralSigningKey();
                }
                else
                {
                    options.AddEncryptionKey(new SymmetricSecurityKey(
                        Convert.FromBase64String(Configuration["EncryptionKey"])));
                    options.AddSigningCertificate(
                        new X509Certificate2(Configuration["Kestrel:Certificates:Default:Path"], Configuration["Kestrel:Certificates:Default:Password"]));
                }

                // Register events handler.
                options.AddEventHandler<ValidateAuthorizationRequestContext>(b => b.UseSingletonHandler<AuthorizationValidator>());
                //
                options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough();
            });
            // .AddValidation(options =>
            // {
            //     if(_env.IsDevelopment())
            //     {
            //         options.UseLocalServer();
            //     }
            //     else
            //     {
            //         options.SetIssuer(Configuration["Services:IdentityUrl"]);
            //         options.AddAudiences("sofisoft");
            //         options.AddEncryptionKey(new SymmetricSecurityKey(
            //             Convert.FromBase64String(Configuration["EncryptionKey"])));
            //     }
                
            //     options.UseSystemNetHttp();
            //     options.UseAspNetCore();
            // });

            services.AddControllers()
                .AddFluentValidation(options =>
                {
                    options.ValidatorOptions.LanguageManager.Culture = new System.Globalization.CultureInfo("es");
                });
            services.AddRazorPages();
            services.AddAntiforgery(o => o.SuppressXFrameOptionsHeader = true);
        }

        public void ConfigureContainer(ContainerBuilder builder)
        {
            builder.RegisterModule(new ApplicationModule(Configuration));
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHttpsRedirection();
            }

            app.UseCors("CorsPolicy");
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseStaticFiles();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapRazorPages();
            });
        }
    }
}
