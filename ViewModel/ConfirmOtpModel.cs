using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using A07_UTS.Data;

namespace A07_UTS.ViewModel
{
    public class ConfirmOTPModel
    {
        [Required(ErrorMessage = "OTP is required")]
        public string OTP { get; set; } = string.Empty;

        public string Username { get; set; }
    }
}
