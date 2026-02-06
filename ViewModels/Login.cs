using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
namespace Assignment2.ViewModels
{
 
    public class Login : IValidatableObject
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        public string? Password { get; set; }

        public bool RememberMe { get; set; }
        
        // Captcha token populated by client when required
        public string? CaptchaToken { get; set; }


        // Optional properties for lockout & auditing
        public int FailedLoginAttempts { get; set; }
        public DateTimeOffset? LockoutEndUtc { get; set; }

        public string? ErrorMessage { get; set; }

        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            if (!string.IsNullOrWhiteSpace(Email) && Email!.Length > 254)
            {
                yield return new ValidationResult("Email is too long.", new[] { nameof(Email) });
            }

            if (!string.IsNullOrWhiteSpace(Password) && Password!.Length > 1024)
            {
                yield return new ValidationResult("Password is too long.", new[] { nameof(Password) });
            }

        }

        public static async Task<bool> VerifyRecaptchaAsync(string token, string secretKey, double minScore = 0.5, HttpClient? httpClient = null)
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(secretKey)) return false;

            using var client = httpClient ?? new HttpClient();
            var url = $"https://www.google.com/recaptcha/api/siteverify?secret={Uri.EscapeDataString(secretKey)}&response={Uri.EscapeDataString(token)}";
            HttpResponseMessage resp;
            try
            {
                resp = await client.GetAsync(url).ConfigureAwait(false);
            }
            catch
            {
                return false;
            }

            if (!resp.IsSuccessStatusCode) return false;

            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (string.IsNullOrEmpty(json)) return false;

            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (!root.TryGetProperty("success", out var successEl) || !successEl.GetBoolean()) return false;
                if (root.TryGetProperty("score", out var scoreEl) && scoreEl.ValueKind == JsonValueKind.Number)
                {
                    var score = scoreEl.GetDouble();
                    return score >= minScore;
                }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
