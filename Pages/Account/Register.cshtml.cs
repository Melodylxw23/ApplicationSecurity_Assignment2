using System;
using System.IO;
using System.Threading.Tasks;
using Assignment2.ViewModels;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Assignment2.Services;

namespace Assignment2.Pages.Account
{
    public class RegisterModel : PageModel
    {
    private readonly IDataProtectionProvider _dpProvider;
    private readonly IWebHostEnvironment _env;
    private readonly Assignment2.Data.ApplicationDbContext _db;
    private readonly IHttpClientFactory _httpFactory;
    private readonly IConfiguration _config;
    private readonly IPasswordHasher _hasher;
        public string RecaptchaSiteKey { get; }

    public RegisterModel(IDataProtectionProvider dpProvider, IWebHostEnvironment env, Assignment2.Data.ApplicationDbContext db, IHttpClientFactory httpFactory, IConfiguration config, IPasswordHasher hasher)
    {
        _dpProvider = dpProvider;
        _env = env;
        _db = db;
        _httpFactory = httpFactory;
        _config = config;
        _hasher = hasher;
        RecaptchaSiteKey = _config["GoogleReCaptcha:SiteKey"] ?? string.Empty;
    }


        [BindProperty]
        public Register Input { get; set; }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Verify reCAPTCHA
            var token = Input.CaptchaToken;
            var secret = _config["GoogleReCaptcha:Secret"];
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(secret) || !await Assignment2.ViewModels.Login.VerifyRecaptchaAsync(token, secret, 0.5, _httpFactory.CreateClient()))
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed. Please try again.");
                return Page();
            }

            // Uniqueness check
            var existing = await _db.Users.FirstOrDefaultAsync(u => u.Email == Input.Email);
            if (existing != null)
            {
                ModelState.AddModelError("Input.Email", "Email already registered.");
                return Page();
            }

            // Protect NRIC
            var protector = _dpProvider.CreateProtector("AceJobAgency.NRIC");
            var protectedNric = Input.ProtectNric(protector);

            // Hash password
            var hashed = _hasher.HashPassword(Input.Password!);

            // Save resume file if present
            // Verify recaptcha if provided - currently disabled
            string? resumePath = null;
            if (Input.Resume != null && Input.Resume.Length > 0)
            {
                // Save under wwwroot/uploads and store a relative web path (/uploads/filename)
                var uploadsDir = Path.Combine(_env.WebRootPath ?? Path.Combine(_env.ContentRootPath, "wwwroot"), "uploads");
                Directory.CreateDirectory(uploadsDir);
                var fileName = Path.GetRandomFileName() + Path.GetExtension(Input.Resume.FileName);
                var physicalPath = Path.Combine(uploadsDir, fileName);
                await using (var fs = System.IO.File.Create(physicalPath))
                {
                    await Input.Resume.CopyToAsync(fs);
                }
                // store web relative path
                resumePath = "/uploads/" + fileName;
            }

            // Sanitize/encode free-text fields before saving to DB to mitigate XSS
            var whoAmIEncoded = string.IsNullOrWhiteSpace(Input.WhoAmI) ? null : System.Net.WebUtility.HtmlEncode(Input.WhoAmI.Trim());
            var firstNameEncoded = string.IsNullOrWhiteSpace(Input.FirstName) ? null : System.Net.WebUtility.HtmlEncode(Input.FirstName.Trim());
            var lastNameEncoded = string.IsNullOrWhiteSpace(Input.LastName) ? null : System.Net.WebUtility.HtmlEncode(Input.LastName.Trim());
            var emailEncoded = string.IsNullOrWhiteSpace(Input.Email) ? null : System.Net.WebUtility.HtmlEncode(Input.Email.Trim());

            var user = new Assignment2.Models.User
            {
                Email = emailEncoded ?? Input.Email!,
                HashedPassword = hashed,
                ProtectedNric = protectedNric,
                FirstName = firstNameEncoded ?? Input.FirstName,
                LastName = lastNameEncoded ?? Input.LastName,
                Gender = Input.Gender.ToString(),
                DateOfBirth = Input.DateOfBirth ?? DateTime.MinValue,
                WhoAmI = whoAmIEncoded,
                ResumePath = resumePath
            };
            // Password age policy: allow immediate change (min 0) and require change after 1 minute (for demo)
            user.MinPasswordAgeMinutes = 0;
            user.MaxPasswordAgeMinutes = 1;
            // record initial password change time so the max-age countdown starts from now
            user.PasswordChangedAt = DateTime.Now;
            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            // Audit log
            _db.AuditLogs.Add(new Assignment2.Models.AuditLog { UserId = user.Id, Action = "Registered", Timestamp = DateTime.Now, Details = "User registered" });
            await _db.SaveChangesAsync();

            return RedirectToPage("/Account/Login");
        }

        // reCAPTCHA verification moved to Assignment2.ViewModels.Login.VerifyRecaptchaAsync
    }
}
