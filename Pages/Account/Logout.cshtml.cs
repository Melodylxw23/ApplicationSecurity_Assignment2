using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Assignment2.Data;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;

namespace Assignment2.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        public LogoutModel(ApplicationDbContext db) { _db = db; }

        public async Task OnPostAsync()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                var userId = int.Parse(User.FindFirst("UserId").Value);
                var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId);
                if (user != null)
                {
                    user.SessionToken = null;
                    user.SessionExpires = null;
                    await _db.SaveChangesAsync();
                }
            }

            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            Response.Redirect("/Account/Login");
        }
    }
}
