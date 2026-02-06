using System;
using System.ComponentModel.DataAnnotations;

namespace Assignment2.Models
{
    public class PasswordHistory
    {
        [Key]
        public int Id { get; set; }
        public int UserId { get; set; }
        [Required]
        public string HashedPassword { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
