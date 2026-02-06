using System;
using System.Linq;
using System.Threading.Tasks;
using Assignment2.Data;
using Assignment2.Models;
using Microsoft.EntityFrameworkCore;

namespace Assignment2.Services
{
    public class AccountSecurityService
    {
        private readonly ApplicationDbContext _db;
        private readonly IPasswordHasher _hasher;

        public AccountSecurityService(ApplicationDbContext db, IPasswordHasher hasher)
        {
            _db = db;
            _hasher = hasher;
        }

        // Check password reuse (last N) - compare plain new password against stored hashed history
        public async Task<bool> IsPasswordReusedAsync(int userId, string newPlainPassword, int historyLimit = 2)
        {
            var hist = await _db.PasswordHistories
                .Where(h => h.UserId == userId)
                .OrderByDescending(h => h.CreatedAt)
                .Take(historyLimit)
                .ToListAsync();

            foreach (var h in hist)
            {
                if (_hasher.VerifyHashedPassword(h.HashedPassword, newPlainPassword)) return true;
            }
            return false;
        }

        public async Task AddPasswordToHistoryAsync(int userId, string hashed)
        {
            _db.PasswordHistories.Add(new PasswordHistory { UserId = userId, HashedPassword = hashed, CreatedAt = DateTime.Now });
            await _db.SaveChangesAsync();

            // Trim history to last N entries (keep most recent first). Default N=2
            var historyLimit = 2;
            var hist = await _db.PasswordHistories.Where(h => h.UserId == userId).OrderByDescending(h => h.CreatedAt).ToListAsync();
            if (hist.Count > historyLimit)
            {
                var toRemove = hist.Skip(historyLimit).ToList();
                _db.PasswordHistories.RemoveRange(toRemove);
                await _db.SaveChangesAsync();
            }
        }

        public string GenerateResetToken()
        {
            return Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        }

        public async Task CreatePasswordResetTokenAsync(int userId, string token, TimeSpan validFor)
        {
            _db.PasswordResetTokens.Add(new PasswordResetToken { UserId = userId, Token = token, ExpiresAt = DateTime.Now.Add(validFor), Used = false });
            await _db.SaveChangesAsync();
        }

        public async Task<PasswordResetToken?> ValidateResetTokenAsync(string token)
        {
            var entry = await _db.PasswordResetTokens.FirstOrDefaultAsync(t => t.Token == token && !t.Used && t.ExpiresAt > DateTime.Now);
            return entry;
        }

        public async Task MarkResetTokenUsedAsync(PasswordResetToken token)
        {
            token.Used = true;
            _db.PasswordResetTokens.Update(token);
            await _db.SaveChangesAsync();
        }
    }
}
