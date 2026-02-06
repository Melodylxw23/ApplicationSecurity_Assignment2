using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using Assignment2.Data;
using Assignment2.Services;
using System.Linq;

namespace Assignment2.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        private readonly AccountSecurityService _sec;
        private readonly IPasswordHasher _hasher;

        public ResetPasswordModel(ApplicationDbContext db, AccountSecurityService sec, IPasswordHasher hasher)
        {
            _db = db; _sec = sec; _hasher = hasher;
        }

        [BindProperty(SupportsGet = true)]
        public string Token { get; set; }
        [BindProperty]
        public string NewPassword { get; set; }

        public void OnGet() { }

        public async Task<IActionResult> OnPostAsync()
        {
            var entry = await _sec.ValidateResetTokenAsync(Token);
            if (entry == null) { ModelState.AddModelError("", "Invalid or expired token"); return Page(); }

            var user = await _db.Users.FindAsync(entry.UserId);
            if (user == null) return Page();

            var reused = await _sec.IsPasswordReusedAsync(user.Id, NewPassword ?? "");
            if (reused) { ModelState.AddModelError("", "Cannot reuse recent passwords"); return Page(); }
            var newHashed = _hasher.HashPassword(NewPassword ?? "");
            await _sec.AddPasswordToHistoryAsync(user.Id, user.HashedPassword);
            user.HashedPassword = newHashed;
            user.PasswordChangedAt = System.DateTime.Now;
            await _db.SaveChangesAsync();

            await _sec.MarkResetTokenUsedAsync(entry);

            return RedirectToPage("/Account/Login");
        }
    }
}
