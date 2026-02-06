using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Assignment2.Data;

namespace Assignment2.Middleware
{
    public class RequirePasswordChangeMiddleware
    {
        private readonly RequestDelegate _next;

        public RequirePasswordChangeMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ApplicationDbContext db, Microsoft.Extensions.Configuration.IConfiguration config)
        {
            try
            {
                if (context.User?.Identity?.IsAuthenticated == true)
                {
                    var userIdClaim = context.User.FindFirst("UserId")?.Value;
                    if (int.TryParse(userIdClaim, out var userId))
                    {
                        var user = await db.Users.FindAsync(userId);
                        if (user != null)
                        {
                            // Determine policy: per-user MaxPasswordAgeMinutes if set, otherwise use global default from configuration
                            int? policyMinutes = user.MaxPasswordAgeMinutes;
                            var def = config["Security:MaxPasswordAgeMinutes"];
                            if (!policyMinutes.HasValue && !string.IsNullOrEmpty(def) && int.TryParse(def, out var d))
                            {
                                policyMinutes = d;
                            }

                            if (policyMinutes.HasValue)
                        {
                                var expired = !user.PasswordChangedAt.HasValue || user.PasswordChangedAt.Value.AddMinutes(policyMinutes.Value) <= DateTime.Now;

                            // allow access to specific endpoints (change/reset/logout/error) without redirect loop
                            var path = context.Request.Path.Value ?? string.Empty;
                            var allow = path.StartsWith("/Account/ChangePassword", StringComparison.OrdinalIgnoreCase)
                                        || path.StartsWith("/Account/ResetPassword", StringComparison.OrdinalIgnoreCase)
                                        || path.StartsWith("/Account/Logout", StringComparison.OrdinalIgnoreCase)
                                        || path.StartsWith("/Error", StringComparison.OrdinalIgnoreCase)
                                        || path.StartsWith("/css/", StringComparison.OrdinalIgnoreCase)
                                        || path.StartsWith("/js/", StringComparison.OrdinalIgnoreCase)
                                        || path.StartsWith("/images/", StringComparison.OrdinalIgnoreCase);

                                if (expired && !allow)
                            {
                                // support both boolean and numeric query values
                                context.Response.Redirect("/Account/ChangePassword?required=true");
                                return;
                            }
                            }
                        }
                    }
                }
            }
            catch
            {
                // don't block request on error
            }

            await _next(context);
        }
    }
}
