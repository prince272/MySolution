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
            var group = app.MapGroup("/account")
                           .WithTags("Account");

            group.MapPost("/create", CreateAccount)
                 .WithName(nameof(CreateAccount))
                 .WithSummary("Create account")
                 .WithDescription("Creates a new user account using an email address or phone number and password.");

            group.MapPost("/signin", SignIn)
                 .WithName(nameof(SignIn))
                 .WithSummary("Sign in with credentials")
                 .WithDescription("Authenticates a user using their email address or phone number and password.");

            group.MapPost("/signin/refresh", SignInWithRefreshToken)
                 .WithName(nameof(SignInWithRefreshToken))
                 .WithSummary("Sign in with refresh token")
                 .WithDescription("Authenticates a user using a refresh token.");

            group.MapPost("/signout", SignOut)
                 .WithName(nameof(SignOut))
                 .WithSummary("Sign out")
                 .WithDescription("Signs out the authenticated user by revoking refresh tokens.");

            group.MapGet("/profile", GetProfile)
                 .WithName(nameof(GetProfile))
                 .WithSummary("Get profile")
                 .WithDescription("Retrieves the profile details of the authenticated user.");

            group.MapPost("/profile", UpdateProfile)
                 .WithName(nameof(UpdateProfile))
                 .WithSummary("Update profile")
                 .WithDescription("Updates the profile details (first name, last name, bio, and more) of the authenticated user.");

            group.MapPost("/send-code", SendVerificationCode)
                 .WithName(nameof(SendVerificationCode))
                 .WithSummary("Send verification code")
                 .WithDescription("Sends a verification code to an email address or phone number for account verification, password reset, or email or phone number change.");

            group.MapPost("/verify", VerifyAccount)
                 .WithName(nameof(VerifyAccount))
                 .WithSummary("Verify email or phone number")
                 .WithDescription("Verifies an email address or phone number using a verification code.");

            group.MapPost("/password/reset", ResetPassword)
                 .WithName(nameof(ResetPassword))
                 .WithSummary("Reset password")
                 .WithDescription("Resets a user password using a verification code sent to an email address or phone number.");

            group.MapPost("/password/change", ChangePassword)
                 .WithName(nameof(ChangePassword))
                 .WithSummary("Change password")
                 .WithDescription("Changes the password of the authenticated user after verifying the current password.");

            group.MapPost("/change", ChangeAccount)
                 .WithName(nameof(ChangeAccount))
                 .WithSummary("Change email or phone number")
                 .WithDescription("Changes the authenticated user's email address or phone number after verifying a code sent to the new email address or phone number.");
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccount(
            IAccountService accountService,
            [FromBody] CreateAccountForm form)
        {
            return accountService.CreateAccountAsync(form);
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignIn(
            IAccountService accountService,
            [FromBody] SignInForm form)
        {
            return accountService.SignInAsync(form);
        }

        public static Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshToken(
            IAccountService accountService,
            [FromBody] SignInWithRefreshTokenForm form)
        {
            return accountService.SignInWithRefreshTokenAsync(form);
        }

        public static Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> SignOut(
            IAccountService accountService,
            [FromBody] SignOutForm form)
        {
            return accountService.SignOutAsync(form);
        }

        public static Task<Results<Ok<ProfileModel>, NotFound, UnauthorizedHttpResult>> GetProfile(
            IAccountService accountService)
        {
            return accountService.GetProfileAsync();
        }

        public static Task<Results<Ok<ProfileModel>, ValidationProblem, UnauthorizedHttpResult>> UpdateProfile(
            IAccountService accountService,
            [FromBody] UpdateProfileForm form)
        {
            return accountService.UpdateProfileAsync(form);
        }

        public static Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> SendVerificationCode(
            IAccountService accountService,
            [FromBody] SendVerificationCodeForm form)
        {
            return accountService.SendVerificationCodeAsync(form);
        }

        public static Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> VerifyAccount(
            IAccountService accountService,
            [FromBody] VerifyAccountForm form)
        {
            return accountService.VerifyAccountAsync(form);
        }

        public static Task<Results<Ok, ValidationProblem, ProblemHttpResult>> ResetPassword(
            IAccountService accountService,
            [FromBody] ResetPasswordForm form)
        {
            return accountService.ResetPasswordAsync(form);
        }

        public static Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> ChangePassword(
            IAccountService accountService,
            [FromBody] ChangePasswordForm form)
        {
            return accountService.ChangePasswordAsync(form);
        }

        public static Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> ChangeAccount(
            IAccountService accountService,
            [FromBody] ChangeAccountForm form)
        {
            return accountService.ChangeAccountAsync(form);
        }
    }
}