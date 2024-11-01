using System.ComponentModel.DataAnnotations;
using System;

namespace A07_UTS.ViewModel;

public class UpdateProfileModel
{
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Contact { get; set; } = string.Empty;
    
}