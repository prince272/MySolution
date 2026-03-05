using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.CacheProvider;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Options;
using MySolution.WebApi.Services.Accounts;
using MySolution.WebApi.Services.Accounts.Models;
using System.Security.Claims;

namespace MySolution.WebApi.Endpoints
{
    public static class AccountEndpoints
    {
        public static void MapAccount(this WebApplication app)
        {
            var group = app.MapGroup("/account")
                           .WithTags("Account");

            group.MapPost("/create", CreateAccount)
                 .WithName(nameof(CreateAccount))
                 .WithSummary("Create account")
                 .WithDescription("Creates a new user account with the Viewer role.");

            group.MapPost("/signin", SignIn)
                 .WithName(nameof(SignIn))
                 .WithSummary("Sign in with credentials")
                 .WithDescription("Authenticates the user with the provided username and password.");

            group.MapPost("/signin/refresh", SignInWithRefreshToken)
                 .WithName(nameof(SignInWithRefreshToken))
                 .WithSummary("Sign in with refresh token")
                 .WithDescription("Revokes the provided refresh token and issues a new one.");

            group.MapGet("/signin/google", SignInWithGoogle)
                 .WithName(nameof(SignInWithGoogle))
                 .WithSummary("Sign in with Google")
                 .WithDescription("Initiates the Google OAuth flow.");

            group.MapGet("/signin/google/callback", SignInWithGoogleCallback)
                 .WithName(nameof(SignInWithGoogleCallback))
                 .WithSummary("Handle Google sign-in callback")
                 .WithDescription("Handles the Google OAuth callback and generates a short-lived signed token.");

            group.MapPost("/signin/google", SignInWithGoogleToken)
                 .WithName(nameof(SignInWithGoogleToken))
                 .WithSummary("Exchange Google token")
                 .WithDescription("Exchanges the short-lived Google OAuth token. Creates the user account if it does not exist.");

            group.MapPost("/signout", SignOut)
                 .WithName(nameof(SignOut))
                 .WithSummary("Sign out")
                 .WithDescription("Revokes the provided refresh token. If RevokeAllTokens is true, resets the security stamp, invalidating all active sessions.");

            group.MapGet("/profile", GetProfile)
                 .WithName(nameof(GetProfile))
                 .WithSummary("Get profile")
                 .WithDescription("Fetches the authenticated user's profile.");

            group.MapPut("/profile", UpdateProfile)
                 .WithName(nameof(UpdateProfile))
                 .WithSummary("Update profile")
                 .WithDescription("Partially updates the authenticated user's profile.");

            group.MapPost("/send-code", SendSecurityCode)
                 .WithName(nameof(SendSecurityCode))
                 .WithSummary("Send security code")
                 .WithDescription("Sends a time-limited security code to the specified email or phone. Enforces a 2-minute cooldown and a maximum of 5 sends per hour.");

            group.MapPost("/verify-code", VerifySecurityCode)
                 .WithName(nameof(VerifySecurityCode))
                 .WithSummary("Verify security code")
                 .WithDescription("Applies the requested action: VerifyAccount, ChangeAccount, or ResetPassword. Resets the security stamp on success.");

            group.MapPost("/password/change", ChangePassword)
                 .WithName(nameof(ChangePassword))
                 .WithSummary("Change password")
                 .WithDescription("Sets a new password and resets the security stamp.");
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccount(IAccountService accountService, [FromBody] CreateAccountForm form)
            => accountService.CreateAccountAsync(form);

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignIn(IAccountService accountService, [FromBody] SignInForm form)
             => accountService.SignInAsync(form);

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshToken(IAccountService accountService, [FromBody] SignInWithRefreshTokenForm form)
            => accountService.SignInWithRefreshTokenAsync(form);

        public static Task<Results<ChallengeHttpResult, ProblemHttpResult>> SignInWithGoogle(IAccountService accountService, HttpContext httpContext, LinkGenerator linkGenerator, string returnUrl)
            => accountService.SignInWithProviderAsync("Google", linkGenerator.GetUriByName(httpContext, nameof(SignInWithGoogleCallback), new { returnUrl })!);

        public static Task<Results<RedirectHttpResult, ProblemHttpResult>> SignInWithGoogleCallback(IAccountService accountService, [FromQuery] string returnUrl)
            => accountService.SignInWithProviderCallbackAsync("Google", returnUrl);

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithGoogleToken(IAccountService accountService, [FromForm] SignInWithProviderTokenForm form)
                 => accountService.SignInWithProviderTokenAsync("Google", form);

        public static Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> SignOut(IAccountService accountService, [FromBody] SignOutForm form)
            => accountService.SignOutAsync(form);

        public static Task<Results<Ok<ProfileModel>, UnauthorizedHttpResult>> GetProfile(IAccountService accountService)
            => accountService.GetProfileAsync();

        public static Task<Results<Ok<ProfileModel>, ValidationProblem, UnauthorizedHttpResult>> UpdateProfile(IAccountService accountService, [FromBody] UpdateProfileForm form)
            => accountService.UpdateProfileAsync(form);

        public static Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> SendSecurityCode(IAccountService accountService, [FromBody] SendSecurityCodeForm form)
            => accountService.SendSecurityCodeAsync(form);

        public static Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> VerifySecurityCode(IAccountService accountService, [FromBody] VerifySecurityCodeForm form)
            => accountService.VerifySecurityCodeAsync(form);

        public static Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> ChangePassword(IAccountService accountService, [FromBody] ChangePasswordForm form)
            => accountService.ChangePasswordAsync(form);
    }
}