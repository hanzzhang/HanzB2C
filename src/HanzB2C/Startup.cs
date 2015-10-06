using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Authentication.OpenIdConnect;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.Dnx.Runtime;
using Microsoft.Framework.Configuration;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Logging;
using HanzB2C.Security;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Globalization;


namespace HanzB2C
{
    public class Startup
    {
        public Startup(IHostingEnvironment env, IApplicationEnvironment appEnv)
        {
            var builder = new ConfigurationBuilder(appEnv.ApplicationBasePath)
                .AddJsonFile("config.json")
                .AddJsonFile($"config.{env.EnvironmentName}.json", optional: true);

            if (env.IsDevelopment())
            {
                builder.AddUserSecrets();
            }
            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; set; }
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookieAuthenticationOptions>(options => options.AutomaticAuthentication = true);
            services.Configure<OpenIdConnectAuthenticationOptions>(options => ConfigureOpenIdConnectAuthentication(options));
            services.AddCors();
            services.ConfigureCors(options => options.AddPolicy("AllowAad", p => p.WithOrigins("https://login.microsoftonline.com")));
            services.AddMvc();
        }
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.MinimumLevel = LogLevel.Information;
            loggerFactory.AddConsole();
            loggerFactory.AddDebug();

            // Configure the HTTP request pipeline.

            // Add the following to the request pipeline only in development environment.
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseErrorPage();
            }
            else
            {
                // Add Error handling middleware which catches all application specific errors and
                // send the request to the following path or controller action.
                app.UseErrorHandler("/Home/Error");
            }

            // Add static files to the request pipeline.
            app.UseStaticFiles();

            // Add cookie-based authentication to the request pipeline.
            app.UseCookieAuthentication();

            // Add OpenIdConnect middleware so you can login using Azure AD.
            app.UseOpenIdConnectAuthentication();

            // Add MVC to the request pipeline.
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
        private void ConfigureOpenIdConnectAuthentication(OpenIdConnectAuthenticationOptions options)
        {
            // from original template
            options.AutomaticAuthentication = true;
            options.ClientId = Configuration["Authentication:AzureAd:ClientId"];
            options.Authority = Configuration["Authentication:AzureAd:AADInstance"] + Configuration["Authentication:AzureAd:Tenant"];
            options.PostLogoutRedirectUri = Configuration["Authentication:AzureAd:PostLogoutRedirectUri"];
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.RedirectUri = Configuration["Authentication:AzureAd:PostLogoutRedirectUri"];
            options.Scope = "openid";
            options.ResponseType = "id_token";
            //options.ConfigurationManager = new PolicyConfigurationManager(options.Authority + "/v2.0/.well-known/openid-configuration",
            //    new string[] { "B2C_1_SiUp", "b2c_1_siin", "B2C_1_SiPe" });

            var configurationManager = new PolicyConfigurationManager();
            configurationManager.AddPolicy("common", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration");
            configurationManager.AddPolicy("b2c_1_siup", string.Format(CultureInfo.InvariantCulture, "{0}{1}?p={2}",
                options.Authority, "/v2.0/.well-known/openid-configuration", "b2c_1_siup"));
            configurationManager.AddPolicy("b2c_1_siin", string.Format(CultureInfo.InvariantCulture, "{0}{1}?p={2}",
                options.Authority, "/v2.0/.well-known/openid-configuration", "b2c_1_siin"));
            configurationManager.AddPolicy("b2c_1_sipe", string.Format(CultureInfo.InvariantCulture, "{0}{1}?p={2}",
                options.Authority, "/v2.0/.well-known/openid-configuration", "b2c_1_sipe"));
            options.ConfigurationManager = configurationManager;

            options.TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters()
            {
                //NameClaimType = "name"
                ValidateIssuer = false
            };
            options.Notifications = CreateOpenIdConnectAuthenticationNotifications();
        }
        private OpenIdConnectAuthenticationNotifications CreateOpenIdConnectAuthenticationNotifications()
        {
            return new OpenIdConnectAuthenticationNotifications()
            {
                MessageReceived = (context) =>
                {
                    return Task.FromResult(0);
                },

                RedirectToIdentityProvider = async (context) =>
                {
                    PolicyConfigurationManager mgr = context.Options.ConfigurationManager as PolicyConfigurationManager;
                    OpenIdConnectConfiguration config = null;
                    if (context.HttpContext.Items.ContainsKey("b2cpolicy"))
                    {
                        string policyName = (string)context.HttpContext.Items["b2cpolicy"];
                        config = await mgr.GetConfigurationByPolicyAsync(System.Threading.CancellationToken.None, policyName);
                    }
                    else
                    {
                        config = await mgr.GetConfigurationByPolicyAsync(System.Threading.CancellationToken.None,
                            "common");
                    }

                    if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                    {
                        context.ProtocolMessage.IssuerAddress = config.EndSessionEndpoint;
                    }
                    else
                    {
                        context.ProtocolMessage.IssuerAddress = config.AuthorizationEndpoint;
                    }
                },

                SecurityTokenReceived = (context) =>
                {
                    return Task.FromResult(0);
                },

                SecurityTokenValidated = (context) =>
                {
                    var principal = context.AuthenticationTicket.Principal;
                    var identity = principal.Identities.First();
                    // TODO - We need to figure out what this looks like when multiple emails are sent.  For now, we'll
                    // assume just one.
                    var emails = principal.FindFirst("emails")?.Value
                        ?? principal.FindFirst("preferred_username")?.Value;
                    if (!string.IsNullOrWhiteSpace(emails))
                    {
                        identity.AddClaim(new Claim(ClaimTypes.Email, emails));
                    }

                    // We need to normalize the name claim for the Identity model
                    var name = principal.FindFirst("name")?.Value;
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        identity.AddClaim(new Claim(identity.NameClaimType, name));
                    }

                    var identityProvider = principal.FindFirst(
                        "http://schemas.microsoft.com/identity/claims/identityprovider")?.Value;
                    if (string.IsNullOrWhiteSpace(identityProvider))
                    {
                        // AAD doesn't provide this in B2C, so we'll add one.
                        identity.AddClaim(new Claim("http://schemas.microsoft.com/identity/claims/identityprovider", "aad"));
                        identity.AddClaim(new Claim("survey_tenant", principal.FindFirst("iss")?.Value));
                    }
                    else
                    {
                        // Whenever we use an external auth provider besides AAD, we need to generate a "tenant" identifier,
                        // since those users are in their own tenant.
                        identity.AddClaim(
                            new Claim("survey_tenant", principal.FindFirst("iss")?.Value +
                            principal.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value));
                    }

                    return Task.FromResult(0);
                },

                AuthenticationFailed = (context) =>
                {
                    context.Response.Redirect("/Home/Error");
                    context.HandleResponse(); // Suppress the exception
                    return Task.FromResult(0);
                }
            };
        }
    }
}
