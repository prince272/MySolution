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

        public static bool ValidateCode(string secret, string code, DateTimeOffset timestamp)
            => ValidateCodeWithOptions(secret, code, timestamp, DefaultCodeTimeStep, DefaultWindow, DefaultCodeHashAlgorithm);

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

        public static bool ValidateHash(string input, string hashedInput)
        {
            ArgumentNullException.ThrowIfNull(input, nameof(input));
            ArgumentNullException.ThrowIfNull(hashedInput, nameof(hashedInput));

            return GenerateHash(input) == hashedInput;
        }
        #endregion

        #region Random Generation
        public static string GenerateRandomString(int length, CharacterSet characterSet)
        {
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

            if (characterSet == CharacterSet.None)
                throw new ArgumentException("At least one character set must be specified.", nameof(characterSet));

            string characters = BuildCharacterPool(characterSet);

            var chars = Enumerable.Range(0, length)
                .Select(_ => characters[GenerateRandomNumber(0, characters.Length)]);

            return string.Join(string.Empty, chars);
        }

        private static string BuildCharacterPool(CharacterSet characterSet)
        {
            var pool = new StringBuilder();

            // WholeNumeric supersedes NaturalNumeric to avoid duplicates
            if (characterSet.HasFlag(CharacterSet.WholeNumeric))
                pool.Append("0123456789");
            else if (characterSet.HasFlag(CharacterSet.NaturalNumeric))
                pool.Append("123456789");

            if (characterSet.HasFlag(CharacterSet.LowerAlpha))
                pool.Append("abcdefghijklmnopqrstuvwyxz");

            if (characterSet.HasFlag(CharacterSet.UpperAlpha))
                pool.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");

            return pool.ToString();
        }

        public static class AesOperation
        {
            static AesOperation()
            {
                using Aes myAes = Aes.Create();

                myAes.GenerateKey();
                myAes.GenerateIV();

                MachineKey = myAes.Key;
                MachineIV = myAes.IV;
            }

            private static byte[] MachineKey { get; set; }
            private static byte[] MachineIV { get; set; }

            public static string Encrypt(string plainText)
            {
                return Convert.ToBase64String(EncryptStringToBytes(plainText, MachineKey, MachineIV));
            }

            public static string Decrypt(string cipherText)
            {
                return DecryptStringFromBytes(Convert.FromBase64String(cipherText), MachineKey, MachineIV);
            }

            private static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
            {
                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException(nameof(plainText));
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException(nameof(Key));
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException(nameof(IV));

                using Aes aesAlg = Aes.Create();
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using MemoryStream msEncrypt = new MemoryStream();
                using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                using StreamWriter swEncrypt = new StreamWriter(csEncrypt);

                swEncrypt.Write(plainText);
                swEncrypt.Flush();
                csEncrypt.FlushFinalBlock();

                return msEncrypt.ToArray();
            }

            private static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
            {
                if (cipherText == null || cipherText.Length <= 0)
                    throw new ArgumentNullException(nameof(cipherText));
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException(nameof(Key));
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException(nameof(IV));

                using Aes aesAlg = Aes.Create();
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using MemoryStream msDecrypt = new MemoryStream(cipherText);
                using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using StreamReader srDecrypt = new StreamReader(csDecrypt);

                return srDecrypt.ReadToEnd();
            }
        }

        public static int GenerateRandomNumber(int min, int max)
        {
            return RandomNumberGenerator.GetInt32(min, max);
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


    [Flags]
    public enum CharacterSet
    {
        None = 0,
        NaturalNumeric = 1 << 0,  // 1  → "123456789"
        WholeNumeric = 1 << 1,  // 2  → "0123456789"
        LowerAlpha = 1 << 2,  // 4  → "abcdefghijklmnopqrstuvwyxz"
        UpperAlpha = 1 << 3,  // 8  → "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        // Convenience combinations
        AnyAlpha = LowerAlpha | UpperAlpha,
        Alphanumeric = WholeNumeric | LowerAlpha | UpperAlpha,
        All = NaturalNumeric | WholeNumeric | LowerAlpha | UpperAlpha
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