using Humanizer;
using MapsterMapper;
using Microsoft.AspNetCore.Http.HttpResults;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.CacheProvider;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.JwtTokenProvider;
using MySolution.WebApi.Libraries.MessageSender;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Libraries.ViewRenderer;
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

        public AccountService(
            IUserRepository userRepository, 
            IValidator validator, 
            IMapper mapper, 
            IGlobalizer globalizer, 
            IJwtTokenProvider jwtTokenProvider, 
            IViewRenderer viewRenderer,
            IEnumerable<IMessageSender> messageSender,
            ICacheProvider cacheProvider)
        {
            _userRepository = userRepository;
            _validator = validator;
            _mapper = mapper;
            _globalizer = globalizer;
            _jwtTokenProvider = jwtTokenProvider;
            _viewRenderer = viewRenderer;
            _messageSender = messageSender;
            _cacheProvider = cacheProvider;
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccountAsync(CreateAccountForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.ContainsErrorKey(() => form.Username))
            {
                var userExists = await _userRepository.ExistsByEmailOrPhoneAsync(form.Username, cancellationToken);

                if (userExists)
                {
                    validatorResult.AddError(() => form.Username, $"'{StringParser.DetectContactType(form.Username)?.Humanize() ?? "Username"}' already exists.");
                }
            }

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var currentTime = _globalizer.Time.GetUtcNow();
            var currentRegionCode = _globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            var user = new User()
            {
                Id = Guid.NewGuid().ToString(),
                FirstName = form.FirstName,
                LastName = form.LastName,
                UserName = await TextHelper.GenerateUniqueSlugAsync(form.Username, _userRepository.ExistsByUserNameAsync, cancellationToken: cancellationToken),
                Email = StringParser.TryParseEmail(form.Username, out var emailInfo) ? emailInfo.Address : null,
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

            User? user = null;

            if (!validatorResult.ContainsErrorKey(() => form.Username))
            {
                user = await _userRepository.GetByEmailOrPhoneAsync(form.Username, cancellationToken);

                if (user == null)
                {
                    validatorResult.AddError(() => form.Username, $"'{StringParser.DetectContactType(form.Username)?.Humanize() ?? "Username"}' does not exist.");
                }
            }

            if (!validatorResult.ContainsErrorKey(() => form.Password))
            {
                var passwordVerified = CryptoHelper.ValidateHash(form.Password, user?.PasswordHash);

                if (!passwordVerified)
                {
                    validatorResult.AddError(() => form.Password, "'Password' is incorrect.");
                }

            }

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var token = await _jwtTokenProvider.CreateTokenAsync(user!.Id.ToString(), user.GetUserClaims(), cancellationToken);
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshTokenAsync(SignInWithRefreshTokenForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            User? user = null;

            if (!validatorResult.ContainsErrorKey(() => form.RefreshToken))
            {
                var claimsPrincipal = await _jwtTokenProvider.ValidateTokenAsync(JwtTokenTypes.RefreshToken, form.RefreshToken, cancellationToken);
                var userId = claimsPrincipal?.GetSubject();
                user = !string.IsNullOrWhiteSpace(userId) ? await _userRepository.GetByIdAsync(userId, cancellationToken) : null;

                if (user == null)
                {
                    validatorResult.AddError(() => form.RefreshToken, "'Refresh token' is invalid.");
                }
            }

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            await _jwtTokenProvider.RevokeTokenAsync(user!.Id.ToString(), form.RefreshToken, cancellationToken);
            var token = await _jwtTokenProvider.CreateTokenAsync(user!.Id.ToString(), user.GetUserClaims(), cancellationToken);
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);
        }

        public async Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> SignOutAsync(SignOutForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            if (!_globalizer.User.IsAuthenticated)
            {
                return TypedResults.Unauthorized();
            }

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            if (form.RevokeAllTokens)
            {
                await _jwtTokenProvider.RevokeAllTokensAsync(_globalizer.User.Id, cancellationToken);
            }
            else
            {
                await _jwtTokenProvider.RevokeTokenAsync(_globalizer.User.Id, form.RefreshToken!, cancellationToken);
            }

            return TypedResults.Ok();
        }

        public async Task<Results<Ok<ProfileModel>, NotFound, UnauthorizedHttpResult>> GetProfileAsync(CancellationToken cancellationToken = default)
        {
            if (!_globalizer.User.IsAuthenticated)
            {
                return TypedResults.Unauthorized();
            }

            var user = await _userRepository.GetByIdAsync(_globalizer.User.Id);

            if (user == null)
                return TypedResults.NotFound();

            var model = _mapper.Map<ProfileModel>(user);
            return TypedResults.Ok(model);
        }

        public async Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> SendVerificationCodeAsync(SendVerificationCodeForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form, nameof(form));

            if (form.Reason == VerificationCodeReason.ChangeAccount)
            {
                if (!_globalizer.User.IsAuthenticated)
                    return TypedResults.Unauthorized();
            }

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (form.Reason == VerificationCodeReason.ChangeAccount)
            {
                var newUsernameExists = !string.IsNullOrWhiteSpace(form.NewUsername) && await _userRepository.ExistsByEmailOrPhoneAsync(form.NewUsername, cancellationToken);

                if (newUsernameExists)
                {
                    validatorResult.AddError(() => form.NewUsername, $"'{StringParser.DetectContactType(form.NewUsername)?.Humanize() ?? "Username"}' is already in use.");
                    return TypedResults.ValidationProblem(validatorResult.Errors);
                }
            }

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var contactType = StringParser.DetectContactType(form.Username) ?? throw new InvalidOperationException($"Unable to determine contact type for username '{form.Username}'.");
            var (channel, templatePrefix) = contactType switch
            {
                ContactType.Email => (MessageChannel.Email, "Email"),
                ContactType.PhoneNumber => (MessageChannel.Sms, "Sms"),
                _ => throw new InvalidOperationException($"Unsupported contact type '{contactType}'.")
            };

            var cooldownKey = $"vc:cooldown:{form.Username}:{form.Reason}".ToLowerInvariant();
            var attemptKey = $"vc:attempts:{form.Username}:{form.Reason}".ToLowerInvariant();
            var cooldown = TimeSpan.FromMinutes(2);

            var lastSent = await _cacheProvider.GetAsync(cooldownKey, () => Task.FromResult<DateTimeOffset?>(null));

            if (lastSent.HasValue)
            {
                var elapsed = _globalizer.Time.GetUtcNow() - lastSent.Value;

                if (elapsed < cooldown)
                {
                    var remaining = cooldown - elapsed;
                    return TypedResults.Problem($"A code was recently sent. Please wait {remaining.Humanize(precision: 2, minUnit: TimeUnit.Second)} before requesting another.");
                }
            }

            var attemptCount = await _cacheProvider.IncrementAsync(attemptKey, 1, TimeSpan.FromHours(1), cancellationToken);

            if (attemptCount > 5)
            {
                return TypedResults.Problem("Too many verification codes have been requested. Please try again later.");
            }

            var user = await _userRepository.GetByEmailOrPhoneAsync(form.Username, cancellationToken);

            if (user == null)
                return TypedResults.Ok();

            var secretKey = CryptoHelper.GenerateHash(string.Join(string.Empty, _globalizer.Device.Id, form.Username, form.Reason, form.NewUsername));

            var subject = form.Reason switch
            {
                VerificationCodeReason.VerifyAccount => "Verify your account",
                VerificationCodeReason.ChangeAccount => "Confirm your account change",
                VerificationCodeReason.ResetPassword => "Reset your password",
                _ => string.Empty
            };
            var code = CryptoHelper.GenerateCode(secretKey, _globalizer.Time.GetUtcNow());
            var body = await _viewRenderer.RenderAsync($"{templatePrefix}/VerificationCode", (form, subject, code, user), cancellationToken: cancellationToken);

            await _messageSender.SendAsync(channel, new Message
            {
                To = form.Username,
                Subject = subject,
                Body = body
            }, cancellationToken);

            await _cacheProvider.SetAsync(cooldownKey, () => Task.FromResult<DateTimeOffset?>(_globalizer.Time.GetUtcNow()), cooldown, cancellationToken);

            return TypedResults.Ok();
        }
    }

    public interface IAccountService
    {
        Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccountAsync(CreateAccountForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok<AccountModel>, ValidationProblem>> SignInAsync(SignInForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshTokenAsync(SignInWithRefreshTokenForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok, ValidationProblem, UnauthorizedHttpResult>> SignOutAsync(SignOutForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok<ProfileModel>, NotFound, UnauthorizedHttpResult>> GetProfileAsync(CancellationToken cancellationToken = default);
        Task<Results<Ok, ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> SendVerificationCodeAsync(SendVerificationCodeForm form, CancellationToken cancellationToken = default);
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

        public static string? GetEmail(this ClaimsPrincipal principal)
        {
            return principal.FindFirstValue(EmailClaimType);
        }

        public static string? GetPhoneNumber(this ClaimsPrincipal principal)
        {
            return principal.FindFirstValue(PhoneNumberClaimType);
        }

        public static IEnumerable<string> GetRoles(this ClaimsPrincipal principal)
        {
            return principal.FindAll(RoleClaimType).Select(c => c.Value);
        }

        public static bool HasRole(this ClaimsPrincipal principal, string role)
        {
            return principal.FindAll(RoleClaimType).Any(c => c.Value == role);
        }
    }
}
