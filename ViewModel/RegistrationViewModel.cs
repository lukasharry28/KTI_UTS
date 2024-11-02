using System;
using System.ComponentModel.DataAnnotations;

namespace A07_UTS.ViewModel;

public class RegistrationViewModel
{
    [Required]
    public string? Username { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [MinLength(12, ErrorMessage = "Password must be at least 12 characters long")]
    [MaxLength(100, ErrorMessage = "Password must not exceed 64 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$", ErrorMessage = "Password must contain at least one uppercase letter, one lowercase letter, and one number.")]
    public string? Password { get; set; }

    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm Password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string? ConfirmPassword { get; set; }
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
        {
            var validationResults = new List<ValidationResult>();

            if (Password.Length < 12)
            {
                validationResults.Add(new ValidationResult("Password must be at least 12 characters long", new[] { "Password" }));
            }

            if (!Password.Any(char.IsUpper))
            {
                validationResults.Add(new ValidationResult("Password must contain at least one uppercase letter", new[] { "Password" }));
            }

            if (!Password.Any(char.IsLower))
            {
                validationResults.Add(new ValidationResult("Password must contain at least one lowercase letter", new[] { "Password" }));
            }

            if (!Password.Any(char.IsDigit))
            {
                validationResults.Add(new ValidationResult("Password must contain at least one number", new[] { "Password" }));
            }

            return validationResults;
        }

    [Required]
    public string? Email { get; set; }

    [Required]
    public string? Contact { get; set; }
}
