using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;

namespace Assignment2.Pages.Error
{
    public class IndexModel : PageModel
    {
        [FromRoute]
        public int StatusCode { get; set; }

        public string Message { get; set; } = "An error occurred.";

        public void OnGet()
        {
            Message = StatusCode switch
            {
                400 => "Bad request. The server could not understand the request.",
                401 => "Unauthorized. You need to log in to access this resource.",
                403 => "Forbidden. You do not have permission to access this resource.",
                404 => "Not found. The requested resource was not found.",
                500 => "Internal server error. Please try again later.",
                _ => "An unexpected error occurred."
            };
        }
    }
}
