using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using Assignment2.Data;
using Microsoft.AspNetCore.DataProtection;
using System.Text.Encodings.Web;

namespace Assignment2.Pages.Account
{
    public class Enable2faModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        private readonly IDataProtectionProvider _dp;

        public Enable2faModel(ApplicationDbContext db, IDataProtectionProvider dp)
        {
            _db = db; _dp = dp;
        }

        [BindProperty]
        public string? Secret { get; set; }

        [BindProperty]
        public string? Code { get; set; }

        public string? OtpauthUri { get; set; }

        public void OnGet()
        {
            // generate secret
            Secret = Assignment2.Services.TotpHelper.GenerateSecretBase32(20);
            var issuer = "AceJobAgency";
            var label = $"{issuer}:{User?.Identity?.Name ?? "user"}";
            // Build otpauth URI and URL-encode label and issuer
            var enc = UrlEncoder.Default;
            OtpauthUri = $"otpauth://totp/{enc.Encode(label)}?secret={Secret}&issuer={enc.Encode(issuer)}&algorithm=SHA1&digits=6&period=30";
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!User.Identity?.IsAuthenticated == true) return RedirectToPage("/Account/Login");
            var userIdClaim = User.FindFirst("UserId")?.Value;
            if (!int.TryParse(userIdClaim, out var userId)) return RedirectToPage("/Account/Login");
            var user = await _db.Users.FindAsync(userId);
            if (user == null) return RedirectToPage("/Account/Login");

            if (string.IsNullOrWhiteSpace(Secret) || string.IsNullOrWhiteSpace(Code))
            {
                ModelState.AddModelError(string.Empty, "Secret and code required.");
                return Page();
            }

            if (!Assignment2.Services.TotpHelper.VerifyCode(Secret, Code, 30, 1))
            {
                ModelState.AddModelError(string.Empty, "Invalid code.");
                return Page();
            }

            var protector = _dp.CreateProtector("TwoFactor.Secret");
            user.TwoFactorSecret = protector.Protect(Secret);
            user.TwoFactorEnabled = true;
            await _db.SaveChangesAsync();

            // After enabling 2FA, redirect back to profile
            return RedirectToPage("/Account/Profile");
        }
    }
}
