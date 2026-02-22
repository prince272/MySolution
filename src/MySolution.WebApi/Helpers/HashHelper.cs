using BCrypt.Net;
using System.Security.Cryptography;
using System.Text;

namespace MySolution.WebApi.Helpers
{
    public static class HashHelper
    {
        public static string HashInput(string input)
        {
            ArgumentNullException.ThrowIfNull(input);

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

        public static bool CheckInput(string password, string? hashedPassword)
        {
            return HashInput(password) == hashedPassword;
        }
    }
}