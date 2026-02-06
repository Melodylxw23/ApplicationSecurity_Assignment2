using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using Assignment2.Data;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;

namespace Assignment2.Pages.Account
{
    public class Verify2faModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        private readonly IDataProtectionProvider _dp;

        public Verify2faModel(ApplicationDbContext db, IDataProtectionProvider dp)
        {
            _db = db; _dp = dp;
        }

        [BindProperty]
        public string? Code { get; set; }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            var userId = HttpContext.Session.GetInt32("2fa_user");
            if (!userId.HasValue) return RedirectToPage("/Account/Login");
            var user = await _db.Users.FindAsync(userId.Value);
            if (user == null) return RedirectToPage("/Account/Login");

            if (string.IsNullOrWhiteSpace(user.TwoFactorSecret)) return RedirectToPage("/Account/Login");
            var protector = _dp.CreateProtector("TwoFactor.Secret");
            var secret = protector.Unprotect(user.TwoFactorSecret!);
            var secretBytes = Assignment2.Services.TotpHelper.FromBase32(secret);
            if (!Assignment2.Services.TotpHelper.VerifyCode(secret, Code ?? string.Empty, 30, 1))
            {
                ModelState.AddModelError("", "Invalid code");
                return Page();
            }

            // sign in
            var claims = new[] { new Claim(ClaimTypes.Name, user.Email), new Claim("UserId", user.Id.ToString()) };
            if (!string.IsNullOrEmpty(user.SessionToken))
            {
                claims = new[] { new Claim(ClaimTypes.Name, user.Email), new Claim("UserId", user.Id.ToString()), new Claim("SessionToken", user.SessionToken) };
            }
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            var remember = HttpContext.Session.GetInt32("2fa_remember") == 1;
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties { IsPersistent = remember, ExpiresUtc = DateTimeOffset.Now.AddMinutes(30) });

            // clear session keys
            HttpContext.Session.Remove("2fa_user");
            HttpContext.Session.Remove("2fa_remember");

            return RedirectToPage("/Dashboard");
        }
    }
}
