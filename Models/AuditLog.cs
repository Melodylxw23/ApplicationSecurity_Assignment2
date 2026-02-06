using System;
using System.ComponentModel.DataAnnotations;

namespace Assignment2.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }
        public int? UserId { get; set; }
        public string Action { get; set; }
        // Keep DB column name but property represents local time
        public DateTime Timestamp { get; set; }
        public string? Details { get; set; }
    }
}
