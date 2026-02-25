using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace MySolution.WebApi.Helpers
{
    public static partial class TextHelper
    {
        [GeneratedRegex(@"[^a-zA-Z0-9\-\.\s_]", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
        private static partial Regex NonAlphanumericRegex();

        [GeneratedRegex(@"[\-\.\s_]", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
        private static partial Regex SymbolsRegex();

        [GeneratedRegex(@"(-){2,}", RegexOptions.None, matchTimeoutMilliseconds: 1000)]
        private static partial Regex DoubleSeparatorRegex();

        public static string GenerateSlug(string input, string separator = "-")
        {
            ArgumentNullException.ThrowIfNull(input, nameof(input));

            static string RemoveDiacritics(string text)
            {
                var normalizedString = text.Normalize(NormalizationForm.FormD);
                var stringBuilder = new StringBuilder();
                foreach (var c in normalizedString)
                {
                    var unicodeCategory = CharUnicodeInfo.GetUnicodeCategory(c);
                    if (unicodeCategory != UnicodeCategory.NonSpacingMark)
                    {
                        stringBuilder.Append(c);
                    }
                }
                return stringBuilder.ToString().Normalize(NormalizationForm.FormC);
            }

            // Remove all diacritics.
            input = RemoveDiacritics(input);
            // Remove everything that's not a letter, number, hyphen, dot, whitespace or underscore.
            input = NonAlphanumericRegex().Replace(input, string.Empty).Trim();
            // Replace symbols with a separator.
            input = SymbolsRegex().Replace(input, separator ?? string.Empty);
            // Replace double occurrences of separator.
            input = DoubleSeparatorRegex().Replace(input, "$1").Trim('-');

            return input;
        }

        public static async Task<string> GenerateUniqueSlugAsync(string input, Func<string, CancellationToken, Task<bool>> exists, string separator = "-", CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(input, nameof(input));
            ArgumentNullException.ThrowIfNull(exists, nameof(exists));

            var slug = GenerateSlug(input, separator);

            if (!await exists(slug, cancellationToken))
                return slug;

            var count = 1;
            string candidateSlug;
            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                candidateSlug = GenerateSlug($"{input}{separator}{count}", separator);
                count++;
            }
            while (await exists(candidateSlug, cancellationToken));

            return candidateSlug;
        }
    }
}