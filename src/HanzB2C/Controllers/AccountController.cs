using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Authentication.OpenIdConnect;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Mvc;

using System.Security.Claims;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Identity;
using Microsoft.Data.Entity;
using Microsoft.AspNet.Cors.Core;
using Microsoft.AspNet.Http.Features.Authentication;

namespace HanzB2C.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        [AllowAnonymous]
        public IActionResult SignIn()
        {
            this.Context.Items.Add("b2cpolicy", "b2c_1_siin");

            return new ChallengeResult(
                  OpenIdConnectAuthenticationDefaults.AuthenticationScheme,
                    new AuthenticationProperties(new Dictionary<string, string>() { { "b2cpolicy", "b2c_1_siin" } })
                    {
                        RedirectUri = Url.Action("SignInSuccess", "Account")
                    });
        }

        public IActionResult SignInSuccess()
        {
            var user = this.User;
            return View(this.User.Claims);
        }


        [AllowAnonymous]
        public IActionResult SignUp()
        {
            this.Context.Items.Add("b2cpolicy", "B2C_1_SiUp");
            return new ChallengeResult(
                OpenIdConnectAuthenticationDefaults.AuthenticationScheme,
                new AuthenticationProperties(new Dictionary<string, string>() { { "b2cpolicy", "B2C_1_SiUp" } })
                {
                    RedirectUri = "/"
                    //RedirectUri = Url.Action("ExternalLoginCallback", "Account")
                });
        }

        public async Task<IActionResult> SignOut()
        {
            this.Context.Items.Add("b2cpolicy", "b2c_1_siin");
            await Context.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await Context.Authentication.SignOutAsync(OpenIdConnectAuthenticationDefaults.AuthenticationScheme,
                new AuthenticationProperties
                {
                    RedirectUri = Url.Action("SignOutCallback", "Account", values: null, protocol: Request.Scheme)
                });

            return new EmptyResult();
        }

        [AllowAnonymous]
        public IActionResult SignOutCallback()
        {
            if (Context.User.Identity.IsAuthenticated)
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View();
        }
    }
}
