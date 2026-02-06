using System;
using System.ComponentModel.DataAnnotations;

namespace Assignment2.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        [Required]
        [StringLength(254)]
        public string Email { get; set; }
        [Required]
        public string HashedPassword { get; set; }
        [Required]
        public string ProtectedNric { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Gender { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string? WhoAmI { get; set; }
        public string? ResumePath { get; set; }

        // Account lockout
        public int FailedLoginCount { get; set; }
        // Legacy DB column name is preserved; property exposes local time semantics
        public DateTime? LockoutEnd { get; set; }

        // Session tracking - simple single-session token
        public string? SessionToken { get; set; }
        // Legacy DB column name is preserved; property exposes local time semantics
        public DateTime? SessionExpires { get; set; }
        // Password change tracking
        public DateTime? PasswordChangedAt { get; set; }

        // Minimum/maximum password age enforcement (in minutes)
        public int? MinPasswordAgeMinutes { get; set; }
        public int? MaxPasswordAgeMinutes { get; set; }

        // 2FA
        public bool TwoFactorEnabled { get; set; }
        public string? TwoFactorSecret { get; set; }
    }
}
