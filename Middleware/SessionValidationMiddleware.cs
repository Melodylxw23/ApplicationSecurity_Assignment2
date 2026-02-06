using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Assignment2.Middleware
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, Assignment2.Data.ApplicationDbContext db)
        {
            try
            {
                if (context.User?.Identity?.IsAuthenticated == true)
                {
                    var userIdClaim = context.User.FindFirst("UserId")?.Value;
                    var sessionTokenClaim = context.User.FindFirst("SessionToken")?.Value;

                    if (int.TryParse(userIdClaim, out var userId))
                    {
                        var user = await db.Users.FindAsync(userId);
                        // if user not found or session token mismatch or expired -> sign out
                        if (user == null || string.IsNullOrEmpty(user.SessionToken) || user.SessionToken != sessionTokenClaim || !user.SessionExpires.HasValue || user.SessionExpires.Value < DateTime.Now)
                        {
                            // clear user's stored session server-side
                            if (user != null)
                            {
                                user.SessionToken = null;
                                user.SessionExpires = null;
                                try { await db.SaveChangesAsync(); } catch { }
                            }

                            // sign out the cookie and clear session
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            try { context.Session.Clear(); } catch { }

                            // redirect to login page
                            context.Response.Redirect("/Account/Login?sessionExpired=1");
                            return;
                        }
                    }
                }
            }
            catch
            {
                // if middleware fails, ensure we don't block request processing
            }

            await _next(context);
        }
    }
}
