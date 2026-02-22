using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MySolution.WebApi.Services.Identity;
using MySolution.WebApi.Services.Identity.Models;

namespace MySolution.WebApi.Endpoints
{
    public static class IdentityEndpoints
    {
        public static void MapIdentity(this WebApplication app)
        {
            var group = app.MapGroup("/identity");

            group.MapPost("/create-account", CreateAccount)
                 .WithName(nameof(CreateAccount));

            group.MapPost("/signin", SignIn)
                 .WithName(nameof(SignIn));

            group.MapPost("/signin/refresh", SignInWithRefreshToken)
                 .WithName(nameof(SignInWithRefreshToken));
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccount(IIdentityService identityService, [FromBody] CreateAccountForm form)
        {
            return identityService.CreateAccountAsync(form);
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignIn(IIdentityService identityService, [FromBody] SignInForm form)
        {
            return identityService.SignInAsync(form);
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshToken(IIdentityService identityService, [FromBody] SignInWithRefreshTokenForm form)
        {
            return identityService.SignInWithRefreshTokenAsync(form);
        }
    }
}