using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace Assignment2.ViewModels
{
    public enum GenderType
    {
        Male,
        Female
    }

    public class Register : IValidatableObject
    {
        private const int MinPasswordLength = 12;
        private const long MaxResumeBytes = 5 * 1024 * 1024; // 5 MB

        [Required]
        [MinLength(2, ErrorMessage = "First name must be at least 2 characters.")]
        [StringLength(100)]
        public string? FirstName { get; set; }

        [Required]
        [MinLength(2, ErrorMessage = "Last name must be at least 2 characters.")]
        [StringLength(100)]
        public string? LastName { get; set; }

        [Required]
        public GenderType Gender { get; set; }

        // NRIC should be encrypted before persisting. Keep plain value here for protection step in handler.
        [Required]
        [StringLength(64, ErrorMessage = "NRIC is too long.")]
        public string? NRIC { get; set; }

        [Required]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        [StringLength(254)]
        public string? Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string? Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
        public string? ConfirmPassword { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime? DateOfBirth { get; set; }

        // Resume upload (.pdf or .docx)
        [Required]
        public IFormFile? Resume { get; set; }

        // Free text field allowing special characters; escape/encode before display or storage as needed.
        [DataType(DataType.MultilineText)]
        [StringLength(2000, ErrorMessage = "WhoAmI is too long.")]
        public string? WhoAmI { get; set; }

        // Optional: captcha token - validation disabled for now
        // Optional: captcha token - populated by client and validated server-side when enabled
        public string? CaptchaToken { get; set; }

        // Implement server-side validation logic that requires access to services via ValidationContext
        public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            // Date of birth checks
            if (DateOfBirth.HasValue)
            {
                var dob = DateOfBirth.Value.Date;
                if (dob > DateTime.Now.Date)
                {
                    yield return new ValidationResult("Date of birth cannot be in the future.", new[] { nameof(DateOfBirth) });
                }

                var age = CalculateAge(dob, DateTime.Now.Date);
                if (age < 13)
                {
                    yield return new ValidationResult("You must be at least 13 years old to register.", new[] { nameof(DateOfBirth) });
                }
            }

            // Password complexity checks (server-side enforcement)
            if (string.IsNullOrEmpty(Password))
            {
                yield return new ValidationResult("Password is required.", new[] { nameof(Password) });
            }
            else
            {
                var (ok, reason) = ValidatePasswordStrength(Password);
                if (!ok)
                {
                    yield return new ValidationResult(reason ?? "Password does not meet complexity requirements.", new[] { nameof(Password) });
                }
            }

            // Resume validation
            if (Resume != null)
            {
                if (Resume.Length == 0)
                {
                    yield return new ValidationResult("Uploaded resume is empty.", new[] { nameof(Resume) });
                }
                else if (Resume.Length > MaxResumeBytes)
                {
                    yield return new ValidationResult("Resume file is too large (max 5 MB).", new[] { nameof(Resume) });
                }
                else
                {
                    var fileName = Resume.FileName ?? string.Empty;
                    var ext = Path.GetExtension(fileName).ToLowerInvariant();
                    var allowed = new[] { ".pdf", ".docx" };
                    if (Array.IndexOf(allowed, ext) < 0)
                    {
                        yield return new ValidationResult("Resume must be a .pdf or .docx file.", new[] { nameof(Resume) });
                    }
                }
            }

            // Email length sanity check
            if (!string.IsNullOrWhiteSpace(Email) && Email!.Length > 254)
            {
                yield return new ValidationResult("Email is too long.", new[] { nameof(Email) });
            }

            // Uniqueness check for email cannot be reliably performed here without a service; if a service is registered
            // we attempt to resolve `IUserEmailChecker` or `IUserService` from ValidationContext.GetService.
            // Page handler should also enforce unique email at persistence layer and return a ModelState error when duplicated.
            var emailChecker = validationContext.GetService(typeof(IUserEmailChecker)) as IUserEmailChecker;
            if (emailChecker != null && !string.IsNullOrWhiteSpace(Email))
            {
                if (emailChecker.IsEmailInUse(Email))
                {
                    yield return new ValidationResult("Email is already registered.", new[] { nameof(Email) });
                }
            }
        }

        public interface IUserEmailChecker
        {
            bool IsEmailInUse(string email);
        }

        private static int CalculateAge(DateTime dob, DateTime now)
        {
            var age = now.Year - dob.Year;
            if (now < dob.AddYears(age)) age--;
            return age;
        }

        public static (bool ok, string? reason) ValidatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return (false, "Password is required.");
            if (password.Length < MinPasswordLength) return (false, $"Password must be at least {MinPasswordLength} characters long.");
            if (!Regex.IsMatch(password, "[a-z]")) return (false, "Password must contain at least one lowercase letter.");
            if (!Regex.IsMatch(password, "[A-Z]")) return (false, "Password must contain at least one uppercase letter.");
            if (!Regex.IsMatch(password, "\\d")) return (false, "Password must contain at least one digit.");
            if (!Regex.IsMatch(password, "[\\W_]")) return (false, "Password must contain at least one special character.");
            return (true, null);
        }

        // Evaluate password strength for UI feedback (server-side). Returns a score 0-5 and a strength label.
        public enum PasswordStrength
        {
            VeryWeak = 0,
            Weak = 1,
            Medium = 2,
            Strong = 3,
            VeryStrong = 4,
            Excellent = 5
        }

        public static (PasswordStrength strength, int score, string description) EvaluatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return (PasswordStrength.VeryWeak, 0, "Very weak");

            var score = 0;
            if (password.Length >= MinPasswordLength) score++;
            if (Regex.IsMatch(password, "[a-z]")) score++;
            if (Regex.IsMatch(password, "[A-Z]")) score++;
            if (Regex.IsMatch(password, "\\d")) score++;
            if (Regex.IsMatch(password, "[\\W_]")) score++;

            PasswordStrength strength = score switch
            {
                5 => PasswordStrength.Excellent,
                4 => PasswordStrength.VeryStrong,
                3 => PasswordStrength.Strong,
                2 => PasswordStrength.Medium,
                1 => PasswordStrength.Weak,
                _ => PasswordStrength.VeryWeak
            };

            var description = strength switch
            {
                PasswordStrength.Excellent => "Excellent",
                PasswordStrength.VeryStrong => "Very strong",
                PasswordStrength.Strong => "Strong",
                PasswordStrength.Medium => "Medium",
                PasswordStrength.Weak => "Weak",
                _ => "Very weak"
            };

            return (strength, score, description);
        }

        // Protect (encrypt) NRIC before persisting using ASP.NET Core Data Protection
        public string ProtectNric(IDataProtector protector)
        {
            if (protector == null) throw new ArgumentNullException(nameof(protector));
            if (string.IsNullOrEmpty(NRIC)) throw new InvalidOperationException("NRIC is not set.");
            return protector.Protect(NRIC!);
        }

        // Unprotect (decrypt) NRIC for display using IDataProtector
        public static string UnprotectNric(IDataProtector protector, string protectedValue)
        {
            if (protector == null) throw new ArgumentNullException(nameof(protector));
            if (string.IsNullOrEmpty(protectedValue)) throw new ArgumentNullException(nameof(protectedValue));
            return protector.Unprotect(protectedValue);
        }
    }

    // Small abstraction that, if implemented in the app, allows server-side validation to check for duplicate emails
   
}
