using Humanizer;
using Mapster;
using MapsterMapper;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.CacheProvider;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.JwtTokenProvider;
using MySolution.WebApi.Libraries.MessageSender;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Libraries.ViewRenderer;
using MySolution.WebApi.Options;
using MySolution.WebApi.Services.Accounts.Entities;
using MySolution.WebApi.Services.Accounts.Models;
using MySolution.WebApi.Services.Accounts.Repositories;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace MySolution.WebApi.Services.Accounts
{
    public class AccountService : IAccountService
    {
        private readonly IUserRepository _userRepository;
        private readonly IValidator _validator;
        private readonly IMapper _mapper;
        private readonly IGlobalizer _globalizer;
        private readonly IJwtTokenProvider _jwtTokenProvider;
        private readonly IViewRenderer _viewRenderer;
        private readonly IEnumerable<IMessageSender> _messageSender;
        private readonly ICacheProvider _cacheProvider;
        private readonly IAuthenticationSchemeProvider _authSchemeProvider;
        private readonly IAuthenticationService _authService;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IOptions<AllowedOriginsOptions> _allowedOriginsOptions;

        public AccountService(
            IUserRepository userRepository,
            IValidator validator,
            IMapper mapper,
            IGlobalizer globalizer,
            IJwtTokenProvider jwtTokenProvider,
            IViewRenderer viewRenderer,
            IEnumerable<IMessageSender> messageSender,
            ICacheProvider cacheProvider,
            IAuthenticationSchemeProvider schemeProvider,
            IAuthenticationService authService,
            IHttpContextAccessor httpContextAccessor,
            IOptions<AllowedOriginsOptions> allowedOriginsOptions)
        {
            _userRepository = userRepository;
            _validator = validator;
            _mapper = mapper;
            _globalizer = globalizer;
            _jwtTokenProvider = jwtTokenProvider;
            _viewRenderer = viewRenderer;
            _messageSender = messageSender;
            _cacheProvider = cacheProvider;
            _authSchemeProvider = schemeProvider;
            _authService = authService;
            _httpContextAccessor = httpContextAccessor;
            _allowedOriginsOptions = allowedOriginsOptions;
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccountAsync(CreateAccountForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var currentTime = _globalizer.Time.GetUtcNow();
            var currentRegionCode = _globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            var fullName = $"{form.FirstName} {form.LastName}".Trim();

            var user = new User()
            {
                Id = Guid.NewGuid().ToString(),
                FirstName = form.FirstName,
                LastName = form.LastName,
                UserName = await TextHelper.GenerateUniqueSlugAsync(fullName, _userRepository.ExistsByUserNameAsync, cancellationToken: cancellationToken),
                Email = StringParser.TryParseEmail(form.Username, out var emailInfo) ? emailInfo.Address : null,
                PhoneNumber = StringParser.TryParsePhoneNumber(form.Username, currentRegionCode, out var phoneInfo) ? phoneInfo.NationalNumber : null,
                HasPassword = true,
                PasswordHash = CryptoHelper.GenerateHash(form.Password),
                CreatedAt = currentTime,
                LastActiveAt = currentTime
            };

            await _userRepository.AddAsync(user, cancellationToken);
            await _userRepository.AddRolesAsync(user, [RoleName.Viewer], cancellationToken);
            var token = await _jwtTokenProvider.CreateTokenAsync(user.Id.ToString(), user.GetUserClaims(), cancellationToken);
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem>> SignInAsync(SignInForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var user = (User)validatorResult.ContextData[nameof(User)];
            var token = await _jwtTokenProvider.CreateTokenAsync(user.Id.ToString(), user.GetUserClaims(), cancellationToken);
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshTokenAsync(SignInWithRefreshTokenForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var user = (User)validatorResult.ContextData[nameof(User)];

            await _jwtTokenProvider.RevokeRefreshTokenAsync(user.Id.ToString(), form.RefreshToken, cancellationToken);
            var token = await _jwtTokenProvider.CreateTokenAsync(user.Id.ToString(), user.GetUserClaims(), cancellationToken);
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);
        }

        public async Task<Results<ChallengeHttpResult, ProblemHttpResult>> SignInWithProviderAsync(string provider, string returnUrl, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(provider, nameof(provider));
            ArgumentNullException.ThrowIfNull(returnUrl, nameof(returnUrl));

            var scheme = await _authSchemeProvider.GetSchemeAsync(provider);
            if (scheme == null)
                return TypedResults.Problem(title: $"'{provider}' is not a supported external provider.");

            if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var returnUri) ||
                (returnUri.Scheme != Uri.UriSchemeHttp && returnUri.Scheme != Uri.UriSchemeHttps))
                return TypedResults.Problem(title: $"'{returnUrl}' is not a valid URL.");

            var options = _allowedOriginsOptions.Value;
            if (!options.AllowAnyOrigin)
            {
                var returnHost = returnUri.GetLeftPart(UriPartial.Authority);
                if (!options.GetOrigins().Contains(returnHost, StringComparer.OrdinalIgnoreCase))
                    return TypedResults.Problem(title: $"'{returnHost}' is not an allowed origin.");
            }

            return TypedResults.Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, [scheme.Name]);
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem, ProblemHttpResult>> SignInWithProviderCallbackAsync(string provider, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(provider, nameof(provider));

            var result = await _httpContextAccessor.HttpContext!.AuthenticateAsync(IdentityConstants.ExternalScheme);

            if (!result.Succeeded || result.Principal == null)
                return TypedResults.Problem(title: $"'{provider}' authentication failed.");

            await _httpContextAccessor.HttpContext!.SignOutAsync(IdentityConstants.ExternalScheme);

            var username = result.Principal.FindFirstValue(ClaimTypes.MobilePhone) ?? result.Principal.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrWhiteSpace(username))
                return TypedResults.Problem(title: $"'{provider}' authentication failed.");

            var firstName = result.Principal.FindFirstValue(ClaimTypes.GivenName)!;
            var lastName = result.Principal.FindFirstValue(ClaimTypes.Surname);
            var fullName = $"{firstName} {lastName}".Trim();

            var user = await _userRepository.GetByEmailOrPhoneAsync(username, cancellationToken);

            if (user == null)
            {
                var currentTime = _globalizer.Time.GetUtcNow();
                var currentRegionCode = _globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

                user = new User()
                {
                    Id = Guid.NewGuid().ToString(),
                    FirstName = firstName,
                    LastName = lastName,
                    UserName = await TextHelper.GenerateUniqueSlugAsync(fullName, _userRepository.ExistsByUserNameAsync, cancellationToken: cancellationToken),
                    Email = StringParser.TryParseEmail(username, out var emailInfo) ? emailInfo.Address : null,
                    PhoneNumber = StringParser.TryParsePhoneNumber(username, currentRegionCode, out var phoneInfo) ? phoneInfo.NationalNumber : null,
                    HasPassword = false,
                    PasswordHash = null,
                    CreatedAt = currentTime,
                    LastActiveAt = currentTime
                };

                await _userRepository.AddAsync(user, cancellationToken);
                await _userRepository.AddRolesAsync(user, [RoleName.Viewer], cancellationToken);
            }

            var token = await _jwtTokenProvider.CreateTokenAsync(user.Id.ToString(), user.GetUserClaims(), cancellationToken);
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);
        }


        public async Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> SignOutAsync(SignOutForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            if (!_globalizer.User.IsAuthenticated)
                return TypedResults.Unauthorized();

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            if (form.RevokeAllTokens)
            {
                await _jwtTokenProvider.RevokeAllTokensAsync(_globalizer.User.Id, cancellationToken);
                await _jwtTokenProvider.ResetSecurityStampAsync(_globalizer.User.Id, cancellationToken);
            }
            else
            {
                await _jwtTokenProvider.RevokeRefreshTokenAsync(_globalizer.User.Id, form.RefreshToken, cancellationToken);
            }

            return TypedResults.Ok();
        }

        public async Task<Results<Ok<ProfileModel>, UnauthorizedHttpResult>> GetProfileAsync(CancellationToken cancellationToken = default)
        {
            if (!_globalizer.User.IsAuthenticated)
                return TypedResults.Unauthorized();

            var user = await _userRepository.GetByIdAsync(_globalizer.User.Id, cancellationToken);
            if (user == null) return TypedResults.Unauthorized();

            var model = _mapper.Map<ProfileModel>(user);
            return TypedResults.Ok(model);
        }

        public async Task<Results<Ok<ProfileModel>, ValidationProblem, UnauthorizedHttpResult>> UpdateProfileAsync(UpdateProfileForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            if (!_globalizer.User.IsAuthenticated)
                return TypedResults.Unauthorized();

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var user = await _userRepository.GetByIdAsync(_globalizer.User.Id, cancellationToken);
            if (user == null)
                return TypedResults.Unauthorized();

            var config = new TypeAdapterConfig();
            config.NewConfig<UpdateProfileForm, User>()
                .IgnoreNullValues(true);

            form.Adapt(user, config);

            user.UpdatedAt = _globalizer.Time.GetUtcNow();
            await _userRepository.UpdateAsync(user, cancellationToken);

            var model = _mapper.Map<ProfileModel>(user);
            return TypedResults.Ok(model);
        }

        public async Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> SendSecurityCodeAsync(SendSecurityCodeForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            if (form.Reason == SecurityReason.ChangeAccount)
            {
                if (!_globalizer.User.IsAuthenticated)
                    return TypedResults.Unauthorized();
            }

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var targetUsername = form.Reason == SecurityReason.ChangeAccount ? form.NewUsername! : form.CurrentUsername;
            var cooldownCacheKey = $"vc:cooldown:{targetUsername}:{form.Reason}".ToLowerInvariant();
            var attemptCacheKey = $"vc:attempts:{targetUsername}:{form.Reason}".ToLowerInvariant();
            var secretCacheKey = $"vc:secret:{targetUsername}:{form.Reason}".ToLowerInvariant();
            var cooldownTimeSpan = TimeSpan.FromMinutes(2);

            var contactType = StringParser.ParseContactType(targetUsername);
            var (channel, templatePrefix) = contactType switch
            {
                ContactType.Email => (MessageChannel.Email, "Email"),
                ContactType.PhoneNumber => (MessageChannel.Sms, "Sms"),
                _ => throw new InvalidOperationException($"Unsupported contact type '{contactType}'.")
            };

            var lastSentAt = await _cacheProvider.GetAsync(cooldownCacheKey, () => Task.FromResult<DateTimeOffset?>(null), cancellationToken);

            if (lastSentAt.HasValue)
            {
                var elapsed = _globalizer.Time.GetUtcNow() - lastSentAt.Value;

                if (elapsed < cooldownTimeSpan)
                {
                    var remaining = cooldownTimeSpan - elapsed;
                    return TypedResults.Problem(title: $"Please wait {remaining.Humanize(precision: 2, minUnit: TimeUnit.Second)} before requesting another code.", statusCode: StatusCodes.Status400BadRequest);
                }
            }

            var attemptCount = await _cacheProvider.IncrementAsync(attemptCacheKey, 1, TimeSpan.FromHours(1), cancellationToken);

            if (attemptCount > 5)
                return TypedResults.Problem(title: "Too many code sent. Please try again later.", statusCode: StatusCodes.Status400BadRequest);

            var subject = form.Reason switch
            {
                SecurityReason.VerifyAccount => "Verify your account",
                SecurityReason.ChangeAccount => "Confirm your account change",
                SecurityReason.ResetPassword => "Reset your password",
                _ => string.Empty
            };

            var secretKey = await _cacheProvider.SetAsync(secretCacheKey, () => Task.FromResult(CryptoHelper.GenerateRandomString(32, CharacterSet.Alphanumeric)), cooldownTimeSpan, cancellationToken);

            var code = CryptoHelper.GenerateCode(secretKey, _globalizer.Time.GetUtcNow());
            var body = await _viewRenderer.RenderAsync($"{templatePrefix}/SecurityCode", (form, subject, code), cancellationToken: cancellationToken);

            await _messageSender.SendAsync(channel, new Message
            {
                To = targetUsername,
                Subject = subject,
                Body = body
            }, cancellationToken);

            await _cacheProvider.SetAsync(cooldownCacheKey, () => Task.FromResult<DateTimeOffset?>(_globalizer.Time.GetUtcNow()), cooldownTimeSpan, cancellationToken);

            return TypedResults.Ok();
        }

        public async Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> VerifySecurityCodeAsync(VerifySecurityCodeForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            if (form.Reason == SecurityReason.ChangeAccount)
            {
                if (!_globalizer.User.IsAuthenticated)
                    return TypedResults.Unauthorized();
            }

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var targetUsername = form.Reason == SecurityReason.ChangeAccount ? form.NewUsername! : form.CurrentUsername;
            var cooldownCacheKey = $"vc:cooldown:{targetUsername}:{form.Reason}".ToLowerInvariant();
            var attemptCacheKey = $"vc:attempts:{targetUsername}:{form.Reason}".ToLowerInvariant();
            var secretCacheKey = $"vc:secret:{targetUsername}:{form.Reason}".ToLowerInvariant();
            var secretKey = await _cacheProvider.GetAsync(secretCacheKey, () => Task.FromResult<string?>(null), cancellationToken);

            var isCodeValid = secretKey != null && CryptoHelper.ValidateCode(secretKey, form.Code, _globalizer.Time.GetUtcNow());

            if (!isCodeValid)
            {
                return TypedResults.Problem(title: "Invalid or expired code.", statusCode: StatusCodes.Status400BadRequest);
            }

            var user = (User)validatorResult.ContextData[nameof(User)];
            var contactType = StringParser.ParseContactType(targetUsername);
            var securityReason = form.Reason;

            if (securityReason == SecurityReason.VerifyAccount)
            {
                if (contactType == ContactType.Email)
                {
                    user.EmailVerified = true;
                    user.EmailVerifiedAt = _globalizer.Time.GetUtcNow();
                }
                else if (contactType == ContactType.PhoneNumber)
                {
                    user.PhoneNumberVerified = true;
                    user.PhoneNumberVerifiedAt = _globalizer.Time.GetUtcNow();
                }
            }
            else if (securityReason == SecurityReason.ChangeAccount)
            {
                if (contactType == ContactType.Email)
                {
                    user.Email = StringParser.TryParseEmail(form.NewUsername, out var emailInfo) ? emailInfo.Address : null;
                    user.EmailVerified = true;
                    user.EmailVerifiedAt = _globalizer.Time.GetUtcNow();
                }
                else if (contactType == ContactType.PhoneNumber)
                {
                    var currentRegionCode = _globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();
                    user.PhoneNumber = StringParser.TryParsePhoneNumber(form.NewUsername, currentRegionCode, out var phoneInfo) ? phoneInfo.NationalNumber : null;
                    user.PhoneNumberVerified = true;
                    user.PhoneNumberVerifiedAt = _globalizer.Time.GetUtcNow();
                }
            }
            else if (securityReason == SecurityReason.ResetPassword)
            {
                user.PasswordHash = CryptoHelper.GenerateHash(form.NewPassword!);
                user.HasPassword = true;
                user.PasswordChangedAt = _globalizer.Time.GetUtcNow();
            }

            user.UpdatedAt = _globalizer.Time.GetUtcNow();
            await _userRepository.UpdateAsync(user, cancellationToken);
            await _jwtTokenProvider.ResetSecurityStampAsync(user.Id.ToString(), cancellationToken);

            await _cacheProvider.RemoveAsync(cooldownCacheKey, cancellationToken);
            await _cacheProvider.RemoveAsync(attemptCacheKey, cancellationToken);
            await _cacheProvider.RemoveAsync(secretCacheKey, cancellationToken);

            return TypedResults.Ok();
        }

        public async Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> ChangePasswordAsync(ChangePasswordForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            if (!_globalizer.User.IsAuthenticated)
                return TypedResults.Unauthorized();

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var user = (User)validatorResult.ContextData[nameof(User)];
            user.PasswordHash = CryptoHelper.GenerateHash(form.NewPassword);
            user.HasPassword = true;
            user.PasswordChangedAt = _globalizer.Time.GetUtcNow();

            user.UpdatedAt = _globalizer.Time.GetUtcNow();
            await _userRepository.UpdateAsync(user, cancellationToken);
            await _jwtTokenProvider.ResetSecurityStampAsync(user.Id.ToString(), cancellationToken);

            return TypedResults.Ok();
        }
    }

    public class AccountServiceOptions
    {
        public LockoutOptions Lockout { get; set; } = new LockoutOptions();

        public class LockoutOptions
        {
            public bool Enabled { get; set; }

            public int MaxFailedAttempts { get; set; }

            public TimeSpan Duration { get; set; }
        }
    }


    public interface IAccountService
    {
        Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccountAsync(CreateAccountForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok<AccountModel>, ValidationProblem>> SignInAsync(SignInForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshTokenAsync(SignInWithRefreshTokenForm form, CancellationToken cancellationToken = default);
        Task<Results<ChallengeHttpResult, ProblemHttpResult>> SignInWithProviderAsync(string provider, string returnUrl, CancellationToken cancellationToken = default);
        Task<Results<Ok<AccountModel>, ValidationProblem, ProblemHttpResult>> SignInWithProviderCallbackAsync(string provider, CancellationToken cancellationToken = default);
        Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> SignOutAsync(SignOutForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok<ProfileModel>, UnauthorizedHttpResult>> GetProfileAsync(CancellationToken cancellationToken = default);
        Task<Results<Ok<ProfileModel>, ValidationProblem, UnauthorizedHttpResult>> UpdateProfileAsync(UpdateProfileForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> SendSecurityCodeAsync(SendSecurityCodeForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> VerifySecurityCodeAsync(VerifySecurityCodeForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> ChangePasswordAsync(ChangePasswordForm form, CancellationToken cancellationToken = default);
    }

    public static class ClaimsPrincipalExtensions
    {
        private const string SubClaimType = JwtRegisteredClaimNames.Sub;
        private const string EmailClaimType = JwtRegisteredClaimNames.Email;
        private const string PhoneNumberClaimType = JwtRegisteredClaimNames.PhoneNumber;
        private const string RoleClaimType = "role";

        public static List<Claim> GetUserClaims(this User user)
        {
            var claims = new List<Claim>();

            if (!string.IsNullOrWhiteSpace(user.Email))
                claims.Add(new Claim(EmailClaimType, user.Email));

            if (!string.IsNullOrWhiteSpace(user.PhoneNumber))
                claims.Add(new Claim(PhoneNumberClaimType, user.PhoneNumber));

            if (user.Roles != null)
            {
                foreach (var role in user.Roles)
                    claims.Add(new Claim(RoleClaimType, role.Name.ToString()));
            }

            return claims;
        }

        public static string? GetSubject(this ClaimsPrincipal principal)
        {
            return principal.FindFirstValue(SubClaimType);
        }
    }
}