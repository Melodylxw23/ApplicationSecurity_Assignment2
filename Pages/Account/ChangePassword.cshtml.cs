using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using Assignment2.Data;
using Assignment2.Services;

namespace Assignment2.Pages.Account
{
    public class ChangePasswordModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        private readonly AccountSecurityService _sec;
        private readonly IPasswordHasher _hasher;

        public ChangePasswordModel(ApplicationDbContext db, AccountSecurityService sec, IPasswordHasher hasher)
        {
            _db = db; _sec = sec; _hasher = hasher;
        }

        [BindProperty]
        public string OldPassword { get; set; }
        [BindProperty]
        public string NewPassword { get; set; }

        [BindProperty(SupportsGet = true)]
        public bool Required { get; set; }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!User.Identity?.IsAuthenticated == true) return RedirectToPage("/Account/Login");
            var userId = int.Parse(User.FindFirst("UserId").Value);
            var user = await _db.Users.FindAsync(userId);
            if (user == null) return RedirectToPage("/Account/Login");

            if (!_hasher.VerifyHashedPassword(user.HashedPassword, OldPassword ?? ""))
            {
                ModelState.AddModelError("", "Old password is incorrect.");
                return Page();
            }

            // check min password age
            if (user.PasswordChangedAt.HasValue && user.MinPasswordAgeMinutes.HasValue)
            {
                var expires = user.PasswordChangedAt.Value.AddMinutes(user.MinPasswordAgeMinutes.Value);
                if (DateTime.Now < expires)
                {
                    ModelState.AddModelError("", $"You cannot change your password until {expires}.");
                    return Page();
                }
            }

            // check reuse - pass plain new password so service compares against hashed history
            var reused = await _sec.IsPasswordReusedAsync(userId, NewPassword ?? "");
            if (reused)
            {
                ModelState.AddModelError("", "You cannot reuse recent passwords.");
                return Page();
            }
            // update password
            var newHashed = _hasher.HashPassword(NewPassword ?? "");
            await _sec.AddPasswordToHistoryAsync(userId, user.HashedPassword);
            user.HashedPassword = newHashed;
            user.PasswordChangedAt = DateTime.Now;
            // Ensure MinPasswordAgeMinutes is at least 30
            if (!user.MinPasswordAgeMinutes.HasValue || user.MinPasswordAgeMinutes.Value < 2)
            {
                user.MinPasswordAgeMinutes = 2;
            }
            await _db.SaveChangesAsync();

            // If change was required (via query param), redirect back to profile after change
            if (Required)
            {
                return RedirectToPage("/Account/Profile");
            }
            return RedirectToPage("/Account/Profile");
        }
    }
}
