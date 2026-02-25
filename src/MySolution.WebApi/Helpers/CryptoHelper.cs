using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MySolution.WebApi.Helpers
{
    public static class CryptoHelper
    {
        // OTP Defaults
        public const int DefaultCodeTimeStep = 300;
        public const int DefaultCodeDigits = 6;
        public const string DefaultCodeHashAlgorithm = "SHA1";
        public const int DefaultWindow = 1;

        // Token Defaults
        public static readonly TimeSpan DefaultTokenExpiry = TimeSpan.FromMinutes(30);
        public const string DefaultTokenHashAlgorithm = "SHA256";

        #region OTP (TOTP/HOTP)

        public static string GenerateCode(string secret)
            => GenerateCodeWithOptions(secret, DateTimeOffset.UtcNow, DefaultCodeTimeStep, DefaultCodeDigits, DefaultCodeHashAlgorithm);

        public static string GenerateCode(string secret, DateTimeOffset timestamp)
            => GenerateCodeWithOptions(secret, timestamp, DefaultCodeTimeStep, DefaultCodeDigits, DefaultCodeHashAlgorithm);

        public static string GenerateCodeWithOptions(string secret, DateTimeOffset timestamp, int timeStep, int digits, string hashAlgorithm = DefaultCodeHashAlgorithm)
        {
            if (timeStep <= 0)
                throw new ArgumentException("Invalid timeStep: must be greater than 0.");

            if (digits <= 0 || digits > 10)
                throw new ArgumentException("Invalid digits: must be between 1 and 10.");

            ulong counter = (ulong)timestamp.ToUnixTimeSeconds() / (ulong)timeStep;
            return GenerateHotp(Encoding.UTF8.GetBytes(secret), counter, digits, hashAlgorithm);
        }

        public static bool ValidateCode(string secret, string code)
            => ValidateCodeWithOptions(secret, code, DateTimeOffset.UtcNow, DefaultCodeTimeStep, DefaultWindow, DefaultCodeHashAlgorithm);

        public static bool ValidateCodeWithOptions(string secret, string code, DateTimeOffset timestamp, int timeStep, int window, string hashAlgorithm = DefaultCodeHashAlgorithm)
        {
            string cleanCode = code.Trim();

            foreach (char c in cleanCode)
                if (c < '0' || c > '9')
                    throw new ArgumentException("Code must contain only digits.");

            int digits = cleanCode.Length;
            if (digits < 1 || digits > 10)
                throw new ArgumentException("Invalid code length: must be between 1 and 10 digits.");

            ulong counter = (ulong)timestamp.ToUnixTimeSeconds() / (ulong)timeStep;

            for (int i = -window; i <= window; i++)
            {
                string expected = GenerateHotp(Encoding.UTF8.GetBytes(secret), counter + (ulong)i, digits, hashAlgorithm);
                if (expected == cleanCode)
                    return true;
            }

            return false;
        }

        private static string GenerateHotp(byte[] secret, ulong counter, int digits, string hashAlgorithm)
        {
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(counterBytes);

            using HMAC hmac = CreateHmac(hashAlgorithm, secret);
            byte[] hash = hmac.ComputeHash(counterBytes);

            int offset = hash[^1] & 0x0F;
            ulong binCode = ((ulong)(hash[offset] & 0x7F) << 24) |
                            ((ulong)(hash[offset + 1]) << 16) |
                            ((ulong)(hash[offset + 2]) << 8) |
                             (ulong)(hash[offset + 3]);

            ulong otp = binCode % (ulong)Math.Pow(10, digits);
            return otp.ToString().PadLeft(digits, '0');
        }

        #endregion

        #region Token Generation

        public static string GenerateToken<T>(string secret, T data)
            => GenerateTokenWithOptions(secret, data, DefaultTokenExpiry, DateTimeOffset.UtcNow, DefaultTokenHashAlgorithm);

        public static string GenerateTokenWithTime<T>(string secret, T data, DateTimeOffset timestamp)
            => GenerateTokenWithOptions(secret, data, DefaultTokenExpiry, timestamp, DefaultTokenHashAlgorithm);

        public static string GenerateTokenWithExpiry<T>(string secret, T data, TimeSpan expires)
            => GenerateTokenWithOptions(secret, data, expires, DateTimeOffset.UtcNow, DefaultTokenHashAlgorithm);

        public static string GenerateTokenWithExpiryAndTime<T>(string secret, T data, TimeSpan expires, DateTimeOffset timestamp)
            => GenerateTokenWithOptions(secret, data, expires, timestamp, DefaultTokenHashAlgorithm);

        public static string GenerateTokenWithOptions<T>(string secret, T data, TimeSpan expires, DateTimeOffset timestamp, string hashAlgorithm = DefaultTokenHashAlgorithm)
        {
            byte[] secretBytes = Encoding.UTF8.GetBytes(secret);

            var payload = new TokenPayload<T>
            {
                Data = data,
                Timestamp = timestamp,
                Expiry = timestamp + expires
            };

            byte[] jsonData = JsonSerializer.SerializeToUtf8Bytes(payload);
            byte[] sig = Sign(jsonData, secretBytes, hashAlgorithm);

            byte[] tokenBytes = new byte[jsonData.Length + sig.Length];
            Buffer.BlockCopy(jsonData, 0, tokenBytes, 0, jsonData.Length);
            Buffer.BlockCopy(sig, 0, tokenBytes, jsonData.Length, sig.Length);

            return Convert.ToBase64String(tokenBytes);
        }

        public static TokenPayload<T> ValidateToken<T>(string secret, string token)
            => ValidateTokenWithOptions<T>(secret, token, DateTimeOffset.UtcNow, DefaultTokenHashAlgorithm);

        public static TokenPayload<T> ValidateTokenWithTime<T>(string secret, string token, DateTimeOffset timestamp)
            => ValidateTokenWithOptions<T>(secret, token, timestamp, DefaultTokenHashAlgorithm);

        public static TokenPayload<T> ValidateTokenWithOptions<T>(string secret, string token, DateTimeOffset timestamp, string hashAlgorithm = DefaultTokenHashAlgorithm)
        {
            byte[] secretBytes = Encoding.UTF8.GetBytes(secret);

            byte[] raw;
            try { raw = Convert.FromBase64String(token); }
            catch { throw new ArgumentException("Invalid base64 token."); }

            int hmacSize = GetHmacSize(hashAlgorithm);
            if (raw.Length < hmacSize)
                throw new ArgumentException("Token too short.");

            byte[] data = raw[..^hmacSize];
            byte[] sig = raw[^hmacSize..];

            byte[] expectedSig = Sign(data, secretBytes, hashAlgorithm);
            if (!CryptographicOperations.FixedTimeEquals(sig, expectedSig))
                throw new ArgumentException("Invalid signature.");

            TokenPayload<T> payload;
            try { payload = JsonSerializer.Deserialize<TokenPayload<T>>(data)!; }
            catch { throw new ArgumentException("Invalid payload."); }

            if (timestamp > payload.Expiry)
                throw new InvalidOperationException("Token expired.");

            return payload;
        }

        #endregion

        #region Hashing
        public static string GenerateHash(string input)
        {
            ArgumentNullException.ThrowIfNull(input, nameof(input));

            using (var sha256 = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);

                var hashBuilder = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    hashBuilder.Append(hashBytes[i].ToString("x2"));
                }

                return hashBuilder.ToString();
            }
        }

        public static bool ValidateHash(string password, string? hashedPassword)
        {
            return GenerateHash(password) == hashedPassword;
        }
        #endregion

        #region Internal Helpers

        private static HMAC CreateHmac(string algorithm, byte[] secret) => algorithm switch
        {
            "SHA1" => new HMACSHA1(secret),
            "SHA256" => new HMACSHA256(secret),
            "SHA512" => new HMACSHA512(secret),
            _ => throw new ArgumentException($"Unsupported hash algorithm: {algorithm}")
        };

        private static byte[] Sign(byte[] data, byte[] secret, string hashAlgorithm)
        {
            using HMAC hmac = CreateHmac(hashAlgorithm, secret);
            return hmac.ComputeHash(data);
        }

        private static int GetHmacSize(string hashAlgorithm) => hashAlgorithm switch
        {
            "SHA1" => SHA1.HashSizeInBytes,
            "SHA256" => SHA256.HashSizeInBytes,
            "SHA512" => SHA512.HashSizeInBytes,
            _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}")
        };

        #endregion
    }

    public class TokenPayload<T>
    {
        [JsonPropertyName("data")]
        public T Data { get; set; } = default!;

        [JsonPropertyName("timestamp")]
        public DateTimeOffset Timestamp { get; set; }

        [JsonPropertyName("expiry")]
        public DateTimeOffset Expiry { get; set; }
    }
}