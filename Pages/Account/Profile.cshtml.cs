using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using Assignment2.Data;
using Microsoft.AspNetCore.DataProtection;
using System.Threading.Tasks;

namespace Assignment2.Pages.Account
{
    public class ProfileModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        private readonly IDataProtectionProvider _dp;
        private readonly IWebHostEnvironment _env;

        public ProfileModel(ApplicationDbContext db, IDataProtectionProvider dp, IWebHostEnvironment env)
        {
            _db = db;
            _dp = dp;
            _env = env;
        }

        // Exposed properties for the view
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? Gender { get; set; }
        public string? NRIC { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public string? WhoAmI { get; set; }
        public string? ResumePath { get; set; }
        public bool TwoFactorEnabled { get; set; }
        [BindProperty(SupportsGet = true)]
        public string? Filter { get; set; }

        // Total activities for the user
        public int ActivityCount { get; set; }

        // Count after applying filter
        public int FilteredCount { get; set; }

        public System.Collections.Generic.List<Assignment2.Models.AuditLog>? AuditLogs { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            if (!User.Identity?.IsAuthenticated == true)
            {
                return RedirectToPage("/Account/Login");
            }

            var userIdClaim = User.FindFirst("UserId")?.Value;
            if (!int.TryParse(userIdClaim, out var userId))
            {
                return RedirectToPage("/Account/Login");
            }

            var user = await _db.Users.FindAsync(userId);
            if (user == null)
            {
                return RedirectToPage("/Account/Login");
            }

            FirstName = user.FirstName;
            LastName = user.LastName;
            Email = user.Email;
            Gender = user.Gender;
            DateOfBirth = user.DateOfBirth;
            WhoAmI = user.WhoAmI;
            ResumePath = user.ResumePath;
            TwoFactorEnabled = user.TwoFactorEnabled;

            // Unprotect NRIC if a protector exists
            try
            {
                var protector = _dp.CreateProtector("AceJobAgency.NRIC");
                NRIC = Assignment2.ViewModels.Register.UnprotectNric(protector, user.ProtectedNric);
            }
            catch
            {
                NRIC = "(unable to decrypt)";
            }

            // Load counts and recent audit logs for this user
            ActivityCount = await _db.AuditLogs.Where(a => a.UserId == userId).CountAsync();

            var query = _db.AuditLogs.Where(a => a.UserId == userId);
            if (!string.IsNullOrEmpty(Filter) && !string.Equals(Filter, "All", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(Filter, "Security", StringComparison.OrdinalIgnoreCase))
                {
                    // security-related actions
                    query = query.Where(a => a.Action == "Login" || a.Action == "Logout" || a.Action == "PasswordChange");
                }
                else
                {
                    query = query.Where(a => a.Action == Filter);
                }
            }

            FilteredCount = await query.CountAsync();

            AuditLogs = await query
                .OrderByDescending(a => a.Timestamp)
                .Take(100)
                .ToListAsync();

            return Page();
        }

        // Disable 2FA (POST)
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostDisable2faAsync()
        {
            if (!User.Identity?.IsAuthenticated == true) return Forbid();
            var userIdClaim = User.FindFirst("UserId")?.Value;
            if (!int.TryParse(userIdClaim, out var userId)) return Forbid();
            var user = await _db.Users.FindAsync(userId);
            if (user == null) return Forbid();

            user.TwoFactorEnabled = false;
            user.TwoFactorSecret = null;
            _db.AuditLogs.Add(new Assignment2.Models.AuditLog { UserId = user.Id, Action = "Disable2FA", Timestamp = DateTime.Now, Details = "User disabled 2FA" });
            await _db.SaveChangesAsync();

            return RedirectToPage();
        }

        // Secure download of resume file for current user
        public async Task<IActionResult> OnGetDownloadAsync()
        {
            if (!User.Identity?.IsAuthenticated == true)
            {
                return Forbid();
            }

            var userIdClaim = User.FindFirst("UserId")?.Value;
            if (!int.TryParse(userIdClaim, out var userId)) return Forbid();

            var user = await _db.Users.FindAsync(userId);
            if (user == null || string.IsNullOrEmpty(user.ResumePath)) return NotFound();

            // Ensure file exists and is within the uploads folder
            try
            {
                // user.ResumePath is a web-relative path like /uploads/filename
                var webPath = user.ResumePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
                var full = Path.Combine(_env.WebRootPath ?? Path.Combine(_env.ContentRootPath, "wwwroot"), webPath);
                if (!System.IO.File.Exists(full)) return NotFound();

                var fileName = Path.GetFileName(full);
                var provider = new Microsoft.AspNetCore.StaticFiles.FileExtensionContentTypeProvider();
                if (!provider.TryGetContentType(full, out var contentType)) contentType = "application/octet-stream";

                var stream = System.IO.File.OpenRead(full);
                // Return inline so browsers that can render PDFs will open them in-browser
                Response.Headers["Content-Disposition"] = $"inline; filename=\"{fileName}\"";
                return File(stream, contentType);
            }
            catch
            {
                return NotFound();
            }
        }

        // Reveal NRIC on demand (POST via AJAX). Returns JSON with decrypted NRIC.
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostRevealNricAsync()
        {
            if (!User.Identity?.IsAuthenticated == true) return Forbid();
            var userIdClaim = User.FindFirst("UserId")?.Value;
            if (!int.TryParse(userIdClaim, out var userId)) return Forbid();
            var user = await _db.Users.FindAsync(userId);
            if (user == null) return NotFound();

            try
            {
                var protector = _dp.CreateProtector("AceJobAgency.NRIC");
                var nric = Assignment2.ViewModels.Register.UnprotectNric(protector, user.ProtectedNric);
                // Optional audit: record that the user revealed their NRIC (do not store the NRIC value)
                try
                {
                    _db.AuditLogs.Add(new Assignment2.Models.AuditLog
                    {
                        UserId = userId,
                        Action = "RevealNRIC",
                        Timestamp = DateTime.Now,
                        Details = $"NRIC revealed to user session from IP {HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"}"
                    });
                    await _db.SaveChangesAsync();
                }
                catch
                {
                    // auditing must not block the main flow; ignore failures
                }
                return new JsonResult(new { success = true, nric });
            }
            catch
            {
                try
                {
                    _db.AuditLogs.Add(new Assignment2.Models.AuditLog
                    {
                        UserId = userId,
                        Action = "RevealNRICFailed",

                        Timestamp = DateTime.Now,
                        Details = "Failed attempt to reveal NRIC"
                    });
                    await _db.SaveChangesAsync();
                }
                catch { }
                return new JsonResult(new { success = false, error = "Unable to decrypt" });
            }
        }
    }
}
