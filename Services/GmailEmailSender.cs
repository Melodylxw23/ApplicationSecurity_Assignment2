using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using MimeKit;
using Google.Apis.Gmail.v1;
using Google.Apis.Gmail.v1.Data;
using Google.Apis.Services;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;

namespace Assignment2.Services

{
    public interface IEmailSender
    {
        Task SendEmailAsync(string toEmail, string subject, string htmlBody);
    }
    public class GmailEmailSender : IEmailSender
    {
        private readonly IConfiguration _config;

        public GmailEmailSender(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string htmlBody)
        {
            var settings = _config.GetSection("EmailSettings");
            string clientId = settings["ClientId"];
            string clientSecret = settings["ClientSecret"];
            string refreshToken = settings["RefreshToken"];
            string userEmail = settings["UserEmail"];

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(refreshToken) || string.IsNullOrEmpty(userEmail))
                throw new InvalidOperationException("Gmail settings are not configured properly.");

            var flow = new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer
            {
                ClientSecrets = new ClientSecrets
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret
                }
            });

            var token = new TokenResponse { RefreshToken = refreshToken };
            var credential = new UserCredential(flow, userEmail, token);

            // Refresh access token
            var cancel = CancellationToken.None;
            var refreshed = await credential.RefreshTokenAsync(cancel).ConfigureAwait(false);

            string accessToken = credential.Token?.AccessToken;
            if (string.IsNullOrWhiteSpace(accessToken))
                throw new InvalidOperationException("Failed to obtain Gmail access token. Verify refresh token and scopes.");

            var mime = new MimeMessage();
            mime.From.Add(new MailboxAddress("No Reply", userEmail));
            mime.To.Add(new MailboxAddress("", toEmail));
            mime.Subject = subject;
            mime.Body = new TextPart("html") { Text = htmlBody };

            byte[] rawBytes;
            using (var ms = new MemoryStream())
            {
                await mime.WriteToAsync(ms, cancel).ConfigureAwait(false);
                rawBytes = ms.ToArray();
            }

            string raw = Convert.ToBase64String(rawBytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');

            var service = new GmailService(new BaseClientService.Initializer
            {
                HttpClientInitializer = credential,
                ApplicationName = "Assignment2"
            });

            var msg = new Message { Raw = raw };
            await service.Users.Messages.Send(msg, "me").ExecuteAsync(cancel).ConfigureAwait(false);
        }
    }
}
