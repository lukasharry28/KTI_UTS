using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using A07_UTS.Data;
using A07_UTS.Models;
using A07_UTS.ViewModel;
using System.Net.Mail;

namespace A07_UTS.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IUser _user;

        private readonly IConfiguration _configuration;


        public AccountController(IConfiguration configuration, IUser user)
        {
            _configuration = configuration;
            _user = user;
        }


        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Register(RegistrationViewModel registrationViewModel)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    if (!IsValidPassword(registrationViewModel.Password))
                    {
                        ModelState.AddModelError("Password", "Password must contain at least one uppercase letter, one lowercase letter, and one number.");
                        return View(registrationViewModel);
                    }

                    var user = new User
                    {
                        Username = registrationViewModel.Username,
                        Password = registrationViewModel.Password,
                        Email = registrationViewModel.Email,
                        Contact = registrationViewModel.Contact,
                        Role = "Contributor"
                    };

                    _user.Registration(user);
                    return RedirectToAction("Login", "Account");
                }
                return View(registrationViewModel);
            }
            catch (System.Exception ex)
            {
                ViewBag.error = ex.Message;
            }
            return View(registrationViewModel);
        }

        private bool IsValidPassword(string password)
        {
            return password.Length >= 12 &&
                   password.Any(char.IsUpper) &&
                   password.Any(char.IsLower) &&
                   password.Any(char.IsDigit);
        }

        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            // HttpContext.Session.Clear();
            return RedirectToAction("Login", "Account");
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginViewModel loginViewModel)
        {
            try
            {
                loginViewModel.ReturnUrl = loginViewModel.ReturnUrl ?? Url.Content("~/");
                var user = new User
                {
                    Username = loginViewModel.Username,
                    Password = loginViewModel.Password
                };

                var loginUser = _user.Login(user);
                if (loginUser == null)
                {
                    ViewBag.error = "Username atau password tidak valid.";
                    return View(loginViewModel);
                }

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Username)
                };

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = loginViewModel.RememberMe
                    }
                );

                return RedirectToAction("Index", "Home");
            }
            catch (System.Exception ex)
            {
                ViewBag.Message = ex.Message;
            }
            return View(loginViewModel);
        }

        public ActionResult ChangePassword()
        {
            var model = new ChangePasswordViewModel
            {
                Username = User.Identity.Name
            };
            return View(model);
        }

        [HttpPost]
        public ActionResult ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid || !IsValidPassword(model.NewPassword))
            {
                if (!IsValidPassword(model.NewPassword))
                {
                    ModelState.AddModelError("NewPassword", "Password must contain at least one uppercase letter, one lowercase letter, and one number.");
                }
                return View(model);
            }

            var user = _user.GetUserByUsername(model.Username);
            if (user == null)
            {
                ModelState.AddModelError("", "Username tidak ditemukan.");
                return View(model);
            }

            if (!BCrypt.Net.BCrypt.Verify(model.OldPassword, user.Password))
            {
                ModelState.AddModelError("", "Password lama salah.");
                return View(model);
            }

            user.Password = BCrypt.Net.BCrypt.HashPassword(model.NewPassword);
            _user.UpdatePassword(user);

            ViewBag.Message = "Password berhasil diubah.";
            return View(model);
        }

        public ActionResult UpdateProfile()
        {
            var username = User.Identity.Name;

            if (string.IsNullOrEmpty(username))
            {
                return RedirectToAction("Login", "Account");
            }

            var user = _user.GetUserByUsername(username);
            if (user == null)
            {
                ViewBag.error = "User not found.";
                return RedirectToAction("Login", "Account");
            }

            var model = new UpdateProfileModel
            {
                Username = user.Username,
                Email = user.Email,
                Contact = user.Contact
            };

            return View(model);
        }

        [HttpPost]
        public ActionResult UpdateProfile(UpdateProfileModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                var existingUser = _user.GetUserByUsername(model.Username);
                if (existingUser != null)
                {
                    existingUser.Email = model.Email;
                    existingUser.Contact = model.Contact;

                    _user.UpdateProfile(existingUser);

                    ViewBag.Message = "Profile updated successfully!";
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ViewBag.error = "User not found.";
                }
            }
            catch (Exception ex)
            {
                ViewBag.error = $"An error occurred: {ex.Message}";
            }

            return View(model);
        }

        private string GenerateOTP()
        {
            Random random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        public void SendOTPToUser(string email, string otp)
        {
            var smtpConfig = _configuration.GetSection("Smtp");
            using (var smtpClient = new SmtpClient(smtpConfig["Host"], int.Parse(smtpConfig["Port"])))
            {
                smtpClient.Credentials = new NetworkCredential(smtpConfig["Username"], smtpConfig["Password"]);
                smtpClient.EnableSsl = true;

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(smtpConfig["Username"]),
                    Subject = "Your OTP Code",
                    Body = $"Your OTP code is: {otp}",
                    IsBodyHtml = true 
                };
                mailMessage.To.Add(email);

                try
                {
                    smtpClient.Send(mailMessage);
                }
                catch (SmtpException ex)
                {
                    Console.WriteLine($"SMTP Exception: {ex.Message}");
                }
            }
        }

        public void SendEmail(string toEmail, string otp)
        {
            var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential("lukasharry280@gmail.com", "akuharry2728lukas"),
                EnableSsl = true,
            };

            var message = new MailMessage
            {
                From = new MailAddress("lukasharry280@gmail.com"),
                Subject = "Your OTP Code",
                Body = $"Your OTP code is: {otp}",
                IsBodyHtml = false,
            };
            message.To.Add(toEmail);

            try
            {
                smtpClient.Send(message);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending email: {ex.Message}");
            }
        }


        [HttpGet]
        public IActionResult ForgotPassword()
        {
            var model = new ForgotPasswordModel();
            return View(model);
        }


        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = _user.GetUserByUsername(model.Username);
            if (user != null)
            {
                var otpCode = GenerateOTP();
                SendOTPToUser(user.Email, otpCode);
                _user.SaveOTP(user.Username, otpCode);

                TempData["Username"] = user.Username;
                return RedirectToAction("ConfirmOTP");
            }

            ModelState.AddModelError("", "Username not found.");
            return View(model);
        }

        public IActionResult ConfirmOTP()
        {
            var username = TempData["Username"]?.ToString();
            return View(new ConfirmOTPModel { Username = username });
        }

        [HttpPost]
        public IActionResult ConfirmOTP(ConfirmOTPModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var isValid = _user.ValidateOTP(model.Username, model.OTP);
            if (isValid)
            {
                TempData["Username"] = model.Username;
                return RedirectToAction("ResetPassword");
            }

            ModelState.AddModelError("", "Invalid or expired OTP.");
            return View(model);
        }

        public IActionResult ResetPassword()
        {
            var username = TempData["Username"]?.ToString();
            return View(new ResetPasswordModel { Username = username });
        }


        [HttpPost]
        public IActionResult ResetPassword(ResetPasswordModel model)
        {
            if (string.IsNullOrWhiteSpace(model.Username) ||
                string.IsNullOrWhiteSpace(model.NewPassword) ||
                string.IsNullOrWhiteSpace(model.ConfirmNewPassword))
            {
                ModelState.AddModelError("", "All fields are required.");
                return View(model);
            }

            if (model.NewPassword != model.ConfirmNewPassword)
            {
                ModelState.AddModelError("", "Passwords do not match.");
                return View(model);
            }

            if (!IsValidPassword(model.NewPassword))
            {
                ModelState.AddModelError("", "Invalid password format.");
                return View(model);
            }

            var user = _user.GetUserByUsername(model.Username);
            if (user != null)
            {
                user.Password = BCrypt.Net.BCrypt.HashPassword(model.NewPassword);
                _user.UpdatePassword(user);
                return RedirectToAction("Login");
            }

            ModelState.AddModelError("", "User not found.");
            return View(model);
        }
    }
}
