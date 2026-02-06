using System.Threading.Tasks;
using Assignment2.ViewModels;
using Assignment2.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Assignment2.Services;
using Assignment2.Models;
using Microsoft.AspNetCore.DataProtection;

namespace Assignment2.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        private readonly IDataProtectionProvider _dp;
        private readonly IHttpClientFactory _httpFactory;
        private readonly IConfiguration _config;
        private readonly IPasswordHasher _hasher;
        public string RecaptchaSiteKey { get; }

        public LoginModel(ApplicationDbContext db, IDataProtectionProvider dp, IHttpClientFactory httpFactory, IConfiguration config, IPasswordHasher hasher)
        {
            _db = db;
            _dp = dp;
            _httpFactory = httpFactory;
            _config = config;
            _hasher = hasher;
            RecaptchaSiteKey = _config["GoogleReCaptcha:SiteKey"] ?? string.Empty;
        }

        [BindProperty]
        public Login Input { get; set; }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == Input.Email);
            // If this account has had multiple failed attempts, require recaptcha verification
            if (user != null && user.FailedLoginCount >= 3)
            {
                var token = Input.CaptchaToken;
                var secret = _config["GoogleReCaptcha:Secret"];
                if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(secret) || !await Login.VerifyRecaptchaAsync(token, secret, 0.5, _httpFactory.CreateClient()))
                {
                    ModelState.AddModelError("", "reCAPTCHA validation required after multiple failed attempts.");
                    return Page();
                }
            }

         
            var user2 = user;
            // continue using 'user' variable
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid credentials.");
                return Page();
            }

            // Automatic recovery: if lockout ended in the past, clear it and reset failed count
            if (user.LockoutEnd.HasValue && user.LockoutEnd <= DateTime.Now)
            {
                user.LockoutEnd = null;
                user.FailedLoginCount = 0;
                await _db.SaveChangesAsync();
            }

            // Check lockout
            if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.Now)
            {
                ModelState.AddModelError("", "Account is locked. Try later.");
                return Page();
            }

            var ok = _hasher.VerifyHashedPassword(user.HashedPassword, Input.Password ?? "");
            if (!ok)
            {
                user.FailedLoginCount++;
                if (user.FailedLoginCount >= 3)
                {
                    user.LockoutEnd = DateTime.Now.AddMinutes(1);
                }
                _db.AuditLogs.Add(new AuditLog { UserId = user.Id, Action = "LoginFailed", Timestamp = DateTime.Now, Details = "Invalid password" });
                await _db.SaveChangesAsync();
                ModelState.AddModelError("", "Invalid credentials.");
                return Page();
            }

            // Successful login
            user.FailedLoginCount = 0;
            user.LockoutEnd = null;
            // Create session token and expiry
            user.SessionToken = System.Guid.NewGuid().ToString();
            user.SessionExpires = DateTime.Now.AddMinutes(1);
            _db.AuditLogs.Add(new AuditLog { UserId = user.Id, Action = "Login", Timestamp = DateTime.Now, Details = "User logged in" });
            await _db.SaveChangesAsync();
            // If user has 2FA enabled, store pending user id in session and redirect to verify page
            if (user.TwoFactorEnabled && !string.IsNullOrEmpty(user.TwoFactorSecret))
            {
                HttpContext.Session.SetInt32("2fa_user", user.Id);
                // keep remember-me choice in session as well
                HttpContext.Session.SetInt32("2fa_remember", Input.RememberMe ? 1 : 0);
                return RedirectToPage("/Account/Verify2fa");
            }

            // Create auth cookie
            var claims = new[] { new Claim(ClaimTypes.Name, user.Email), new Claim("UserId", user.Id.ToString()) };
            // include session token to detect multiple devices
            if (!string.IsNullOrEmpty(user.SessionToken))
            {
                claims = new[] { new Claim(ClaimTypes.Name, user.Email), new Claim("UserId", user.Id.ToString()), new Claim("SessionToken", user.SessionToken) };
            }
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties { IsPersistent = Input.RememberMe, ExpiresUtc = DateTimeOffset.Now.AddMinutes(1) });

            return RedirectToPage("/Dashboard");
        }
    }
}
