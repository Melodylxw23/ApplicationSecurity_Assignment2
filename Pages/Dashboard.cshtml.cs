using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Assignment2.Pages
{
    [Authorize]
    public class DashboardModel : PageModel
    {
        public string WelcomeMessage { get; private set; } = string.Empty;

        public void OnGet()
        {
            var name = User?.Identity?.Name ?? "";
            WelcomeMessage = string.IsNullOrEmpty(name) ? "Welcome!" : $"Welcome back, {name}!";
        }
    }
}
