using Assignment2.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Assignment2.Data
{
    public class ApplicationDbContext : DbContext
    {
        private readonly IConfiguration? _configuration;

        // Constructor used by AddDbContext (DI)
        [ActivatorUtilitiesConstructor]
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        // Optional constructor to match the pattern where IConfiguration is provided
        // Make non-public so the DI container won't consider it when selecting a constructor.
        internal ApplicationDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public DbSet<User> Users { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<Assignment2.Models.PasswordHistory> PasswordHistories { get; set; }
        public DbSet<Assignment2.Models.PasswordResetToken> PasswordResetTokens { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            // If not configured by DI, read connection string from configuration
            if (!optionsBuilder.IsConfigured && _configuration != null)
            {
                var conn = _configuration.GetConnectionString("AuthConnectionString");
                if (!string.IsNullOrEmpty(conn))
                {
                    optionsBuilder.UseSqlServer(conn);
                }
            }

            base.OnConfiguring(optionsBuilder);
        }
    }
}
