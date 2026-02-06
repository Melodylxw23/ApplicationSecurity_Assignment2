using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Assignment2.Services;
using Assignment2.Middleware;
using Assignment2.Data;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddRazorPages();

var isDev = builder.Environment.IsDevelopment();

var conn = builder.Configuration.GetConnectionString("AuthConnectionString");
if (string.IsNullOrEmpty(conn))
    throw new InvalidOperationException("Connection string 'AuthConnectionString' is not configured.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(conn));

builder.Services.AddDataProtection();
// Configure antiforgery and cookie policies to require secure cookies and sane SameSite defaults
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = isDev ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
});
builder.Services.AddHttpClient();

// Register password hasher service
builder.Services.AddSingleton<IPasswordHasher, PasswordHasher>();
builder.Services.AddScoped<Assignment2.Services.AccountSecurityService>();
// Allow configuring a global max password age fallback
builder.Configuration.GetSection("Security");
// Email sender for password resets - use Gmail API sender
builder.Services.AddSingleton<Assignment2.Services.IEmailSender, Assignment2.Services.GmailEmailSender>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "AceJobAuth";
        options.LoginPath = "/Account/Login";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(1);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        // Require Secure for all environments to avoid schemeful same-site issues during testing
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        // Lax is a safe default; if your app needs cross-site sending (e.g., iframes) set to None and ensure Secure is true
        options.Cookie.SameSite = SameSiteMode.Lax;
    });

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    // Always mark session cookie as secure to avoid schemeful SameSite problems
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
});

var app = builder.Build();

// Ensure database is created/migrated
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    db.Database.Migrate();
}

// If behind a reverse proxy (like IIS/IIS Express or a container), enable forwarded headers
// so the app correctly sees the original request scheme (HTTPS) for cookie decisions.
app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor
});

// Show custom status code pages (404, 403, 401, 400)
app.UseStatusCodePagesWithReExecute("/Error/{0}");

// Middleware pipeline
if (!app.Environment.IsDevelopment())
{
    // Route unhandled exceptions to the consolidated error page
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseSession();

// Validate session token on each request
app.UseMiddleware<SessionValidationMiddleware>();
// Require password change middleware (enforces max password age)
app.UseMiddleware<Assignment2.Middleware.RequirePasswordChangeMiddleware>();

app.UseAuthorization();

app.MapRazorPages();

app.Run();
