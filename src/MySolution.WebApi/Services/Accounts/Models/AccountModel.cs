namespace MySolution.WebApi.Services.Accounts.Models
{
    /// <summary>
    /// Account details returned after successful authentication including token information.
    /// </summary>
    public class AccountModel : ProfileModel
    {
        /// <summary>
        /// JWT access token for authenticated requests.
        /// </summary>
        public string AccessToken { get; set; } = null!;
        
        /// <summary>
        /// Date and time when the access token expires.
        /// </summary>
        public DateTimeOffset AccessTokenExpiresAt { get; set; }
        
        /// <summary>
        /// Refresh token for obtaining new access tokens.
        /// </summary>
        public string RefreshToken { get; set; } = null!;
        
        /// <summary>
        /// Date and time when the refresh token expires.
        /// </summary>
        public DateTimeOffset RefreshTokenExpiresAt { get; set; }
    }
}
