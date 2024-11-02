using A07_UTS.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace A07_UTS.ViewModel;
public class ForgotPasswordModel
{
    [BindProperty]
    [Required(ErrorMessage = "Username is required.")]
    public string Username { get; set; }
}

