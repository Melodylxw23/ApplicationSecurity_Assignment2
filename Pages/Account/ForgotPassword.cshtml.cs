using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using Assignment2.Data;
using Assignment2.Services;
using System.Linq;

namespace Assignment2.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        private readonly AccountSecurityService _sec;
        private readonly Assignment2.Services.IEmailSender _emailSender;
        private readonly IConfiguration _config;

        public ForgotPasswordModel(ApplicationDbContext db, AccountSecurityService sec, Assignment2.Services.IEmailSender emailSender, IConfiguration config)
        {
            _db = db; _sec = sec; _emailSender = emailSender; _config = config;
        }

        [BindProperty]
        public string Email { get; set; }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = _db.Users.FirstOrDefault(u => u.Email == Email);

            if (user != null)
            {
                var token = _sec.GenerateResetToken();
                await _sec.CreatePasswordResetTokenAsync(user.Id, token, TimeSpan.FromHours(1));

                // Send reset link via email
                var resetUrl = Url.PageLink(pageName: "/Account/ResetPassword", values: new { token = token });
                var subject = "Password reset";
                var html = $"<p>Click the link below to reset your password (expires in 1 hour):</p><p><a href=\"{resetUrl}\">Reset password</a></p>";
                try
                {
                    await _emailSender.SendEmailAsync(user.Email, subject, html);
                    _db.AuditLogs.Add(new Models.AuditLog { UserId = user.Id, Action = "PasswordResetRequested", Timestamp = DateTime.Now, Details = "Password reset email sent" });
                    await _db.SaveChangesAsync();
                }
                catch
                {
                    // fallback to logging token if email fails
                    _db.AuditLogs.Add(new Models.AuditLog { UserId = user.Id, Action = "PasswordResetRequested", Timestamp = DateTime.Now, Details = $"Reset token: {token}" });
                    await _db.SaveChangesAsync();
                }
            }

            // Always redirect to confirmation page so we don't reveal whether email exists
            return RedirectToPage("/Account/ForgotPasswordConfirmation");
        }
    }
}
