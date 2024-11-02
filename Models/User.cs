using System;
using System.ComponentModel.DataAnnotations;

namespace A07_UTS.Models;

public class User
{
    [Key]
    public string Username { get; set; } = null!;
    public string Password { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Contact { get; set; } = null!;
    public string Role { get; set; } = null!;

    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEndTime { get; set; }

    // OTP Properties
    public string? CurrentOtpCode { get; set; } // OTP yang aktif saat ini
    public DateTime? OtpExpiration { get; set; } // Kedaluwarsa OTP
}
