using Humanizer;
using Mapster;
using MapsterMapper;
using Microsoft.AspNetCore.Http.HttpResults;
using MySolution.WebApi.Helpers;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.JwtToken;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Services.Identity.Entities;
using MySolution.WebApi.Services.Identity.Models;
using MySolution.WebApi.Services.Identity.Repositories;
using Npgsql;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace MySolution.WebApi.Services.Identity
{
    public class IdentityService : IIdentityService
    {
        private readonly IUserRepository _userRepository;
        private readonly IValidator _validator;
        private readonly IMapper _mapper;
        private readonly IGlobalizer _globalizer;
        private readonly IJwtTokenProvider _jwtTokenProvider;

        public IdentityService(IUserRepository userRepository, IValidator validator, IMapper mapper, IGlobalizer globalizer, IJwtTokenProvider jwtTokenProvider)
        {
            _userRepository = userRepository;
            _validator = validator;
            _mapper = mapper;
            _globalizer = globalizer;
            _jwtTokenProvider = jwtTokenProvider;
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccountAsync(CreateAccountForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form);

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            if (!validatorResult.ContainsErrorKey(() => form.Username))
            {
                var userExists = await _userRepository.ExistsByEmailOrPhoneAsync(form.Username, cancellationToken);

                if (userExists)
                {
                    validatorResult.AddError(() => form.Username, $"'{ContactHelper.DetectContactType(form.Username)?.Humanize() ?? "Username"}' already exists.");
                }
            }

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var currentDateTime = _globalizer.Time.GetUtcNow();
            var currentRegionCode = _globalizer.Region.TwoLetterISORegionName.ToUpperInvariant();

            var user = new User()
            {
                Id = Guid.NewGuid(),
                FirstName = form.FirstName,
                LastName = form.LastName,
                UserName = await TextHelper.GenerateUniqueSlugAsync(form.Username, _userRepository.ExistsByUserNameAsync, cancellationToken: cancellationToken),
                Email = ContactHelper.TryParseEmail(form.Username, out var emailInfo) ? emailInfo.Address : null,
                PhoneNumber = ContactHelper.TryParsePhoneNumber(form.Username, currentRegionCode, out var phoneInfo) ? phoneInfo.NationalNumber : null,
                SecurityStamp = Guid.NewGuid(),
                HasPassword = true,
                PasswordHash = HashHelper.HashInput(form.Password),
                CreatedAt = currentDateTime,
                LastActiveAt = currentDateTime
            };

            await _userRepository.AddAsync(user, cancellationToken);
            await _userRepository.AddRolesAsync(user, [RoleName.Viewer], cancellationToken);
            var token = await _jwtTokenProvider.CreateTokenAsync(user.Id.ToString(), user.GetIdentityClaims());
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem>> SignInAsync(SignInForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form);

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            User? user = null;

            if (!validatorResult.ContainsErrorKey(() => form.Username))
            {
                user = await _userRepository.GetByEmailOrPhoneAsync(form.Username, cancellationToken);

                if (user == null)
                {
                    validatorResult.AddError(() => form.Username, $"'{ContactHelper.DetectContactType(form.Username)?.Humanize() ?? "Username"}' does not exist.");
                }
            }

            if (!validatorResult.ContainsErrorKey(() => form.Password))
            {
                var passwordVerified = HashHelper.CheckInput(form.Password, user?.PasswordHash);

                if (!passwordVerified)
                {
                    validatorResult.AddError(() => form.Password, "'Password' is incorrect.");
                }

            }

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            var token = await _jwtTokenProvider.CreateTokenAsync(user!.Id.ToString(), user.GetIdentityClaims());
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);
        }

        public async Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshTokenAsync(SignInWithRefreshTokenForm form, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(form);

            var validatorResult = await _validator.ValidateAsync(form, cancellationToken);

            User? user = null;

            if (!validatorResult.ContainsErrorKey(() => form.RefreshToken))
            {
                var claimsPrincipal = await _jwtTokenProvider.ValidateRefreshTokenAsync(form.RefreshToken);
                var userId = claimsPrincipal?.GetUserId();
                user = userId.HasValue ? await _userRepository.GetByIdAsync(userId.Value, cancellationToken) : null;

                if (user == null)
                {
                    validatorResult.AddError(() => form.RefreshToken, "'Refresh token' is invalid.");
                }
            }

            if (!validatorResult.IsValid)
                return TypedResults.ValidationProblem(validatorResult.Errors);

            await _jwtTokenProvider.RevokeTokenAsync(user!.Id.ToString(), form.RefreshToken);
            var token = await _jwtTokenProvider.CreateTokenAsync(user!.Id.ToString(), user.GetIdentityClaims());
            var userModel = _mapper.Map(token, _mapper.Map<AccountModel>(user));
            return TypedResults.Ok(userModel);

        }
    }

    public interface IIdentityService
    {
        Task<Results<Ok<AccountModel>, ValidationProblem>> CreateAccountAsync(CreateAccountForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok<AccountModel>, ValidationProblem>> SignInAsync(SignInForm form, CancellationToken cancellationToken = default);
        Task<Results<Ok<AccountModel>, ValidationProblem>> SignInWithRefreshTokenAsync(SignInWithRefreshTokenForm form, CancellationToken cancellationToken = default);
    }

    public static class ClaimsPrincipalExtensions
    {
        private const string SubClaimType = JwtRegisteredClaimNames.Sub;
        private const string EmailClaimType = JwtRegisteredClaimNames.Email;
        private const string PhoneNumberClaimType = JwtRegisteredClaimNames.PhoneNumber;
        private const string RoleClaimType = "role";
        private const string SecurityStampClaimType = "security_stamp";

        public static List<Claim> GetIdentityClaims(this User user)
        {
            var claims = new List<Claim>();

            if (!string.IsNullOrWhiteSpace(user.Email))
                claims.Add(new Claim(EmailClaimType, user.Email));

            if (!string.IsNullOrWhiteSpace(user.PhoneNumber))
                claims.Add(new Claim(PhoneNumberClaimType, user.PhoneNumber));

            claims.Add(new Claim(SecurityStampClaimType, user.SecurityStamp.ToString()));

            if (user.Roles != null)
            {
                foreach (var role in user.Roles)
                    claims.Add(new Claim(RoleClaimType, role.Name.ToString()));
            }

            return claims;
        }

        public static bool ValidateIdentity(this ClaimsPrincipal principal, User user)
        {
            if (user == null) return false;

            // Validate UserId (sub)
            var sub = principal.FindFirstValue(SubClaimType);
            if (!Guid.TryParse(sub, out var userId) || userId != user.Id)
                return false;

            // Validate Email
            var email = principal.FindFirstValue(EmailClaimType);
            if (!string.Equals(email, user.Email, StringComparison.OrdinalIgnoreCase))
                return false;

            // Validate Phone Number
            var phone = principal.FindFirstValue(PhoneNumberClaimType);
            if (!string.Equals(phone, user.PhoneNumber, StringComparison.Ordinal))
                return false;

            // Validate Security Stamp
            var stamp = principal.FindFirstValue(SecurityStampClaimType);
            if (!Guid.TryParse(stamp, out var securityStamp) || securityStamp != user.SecurityStamp)
                return false;

            // Validate Roles
            var principalRoles = principal.FindAll(RoleClaimType)
                                          .Select(r => r.Value)
                                          .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var userRoles = user.Roles?
                                .Select(r => r.Name.ToString())
                                .ToHashSet(StringComparer.OrdinalIgnoreCase)
                            ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (!principalRoles.SetEquals(userRoles))
                return false;

            return true;
        }

        public static Guid? GetUserId(this ClaimsPrincipal principal)
        {
            var sub = principal.FindFirstValue(SubClaimType);
            return Guid.TryParse(sub, out var id) ? id : null;
        }

        public static string? GetEmail(this ClaimsPrincipal principal)
        {
            return principal.FindFirstValue(EmailClaimType);
        }

        public static string? GetPhoneNumber(this ClaimsPrincipal principal)
        {
            return principal.FindFirstValue(PhoneNumberClaimType);
        }

        public static Guid? GetSecurityStamp(this ClaimsPrincipal principal)
        {
            var stamp = principal.FindFirstValue(SecurityStampClaimType);
            return Guid.TryParse(stamp, out var id) ? id : null;
        }

        public static IEnumerable<string> GetRoles(this ClaimsPrincipal principal)
        {
            return principal.FindAll(RoleClaimType).Select(c => c.Value);
        }

        public static bool HasRole(this ClaimsPrincipal principal, string role)
        {
            return principal.FindAll(RoleClaimType).Any(c => c.Value == role);
        }

        public static bool HasUserId(this ClaimsPrincipal principal)
        {
            return principal.GetUserId().HasValue;
        }
    }
}
