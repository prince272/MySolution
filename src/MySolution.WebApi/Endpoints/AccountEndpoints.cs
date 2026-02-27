using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using MySolution.WebApi.Services.Accounts;
using MySolution.WebApi.Services.Accounts.Models;

namespace MySolution.WebApi.Endpoints
{
    public static class AccountEndpoints
    {
        public static void MapAccount(this WebApplication app)
        {
            var group = app.MapGroup("/accounts")
                           .WithTags("Accounts");

            group.MapPost("/create", CreateAccount)
                 .WithName(nameof(CreateAccount))
                 .WithSummary("Create a new account")
                 .WithDescription("Registers a new user account. Returns the created account details on success, or validation errors if the form is invalid.")
                 .Produces<AccountModel>(StatusCodes.Status200OK)
                 .ProducesValidationProblem();

            group.MapPost("/signin", SignIn)
                 .WithName(nameof(SignIn))
                 .WithSummary("Sign in with credentials")
                 .WithDescription("Authenticates a user using their email and password. Returns account details including access and refresh tokens on success.")
                 .Produces<AccountModel>(StatusCodes.Status200OK)
                 .ProducesValidationProblem();

            group.MapPost("/signin/refresh", SignInWithRefreshToken)
                 .WithName(nameof(SignInWithRefreshToken))
                 .WithSummary("Sign in with a refresh token")
                 .WithDescription("Issues a new access token using a valid refresh token. Use this to silently re-authenticate without requiring the user's credentials again.")
                 .Produces<AccountModel>(StatusCodes.Status200OK)
                 .ProducesValidationProblem();

            group.MapPost("/signout", SignOut)
                 .WithName(nameof(SignOut))
                 .WithSummary("Sign out")
                 .WithDescription("Invalidates the user's current session and refresh token.")
                 .Produces(StatusCodes.Status200OK)
                 .ProducesValidationProblem();

            group.MapGet("/profile", GetProfile)
                 .WithName(nameof(GetProfile))
                 .WithSummary("Get the current user's profile")
                 .WithDescription("Returns profile information for the authenticated user. Requires a valid Bearer token in the Authorization header.")
                 .Produces<ProfileModel>(StatusCodes.Status200OK)
                 .Produces(StatusCodes.Status404NotFound)
                 .RequireAuthorization();

            group.MapPost("/verification-code/send", SendVerificationCodeAsync)
                 .WithName(nameof(SendVerificationCodeAsync))
                 .WithSummary("Send a verification code")
                 .WithDescription("Sends a verification code to the user's registered email or phone number. Use the code to verify account ownership.")
                 .Produces(StatusCodes.Status200OK)
                 .ProducesValidationProblem();
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccount(IAccountService accountService, [FromBody] CreateAccountForm form)
        {
            return accountService.CreateAccountAsync(form);
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignIn(IAccountService accountService, [FromBody] SignInForm form)
        {
            return accountService.SignInAsync(form);
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshToken(IAccountService accountService, [FromBody] SignInWithRefreshTokenForm form)
        {
            return accountService.SignInWithRefreshTokenAsync(form);
        }

        public static Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> SignOut(IAccountService accountService, [FromBody] SignOutForm form)
        {
            return accountService.SignOutAsync(form);
        }

        public static Task<Results<Ok<ProfileModel>, NotFound, UnauthorizedHttpResult>> GetProfile(IAccountService accountService)
        {
            return accountService.GetProfileAsync();
        }

        public static Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> SendVerificationCodeAsync(IAccountService accountService, [FromBody] SendVerificationCodeForm form)
        {
            return accountService.SendVerificationCodeAsync(form);
        }
    }
}