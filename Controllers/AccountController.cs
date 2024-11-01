using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using A07_UTS.Data;
using A07_UTS.Models;
using A07_UTS.ViewModel;

namespace A07_UTS.Controllers
{
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly IUser _user;

        public AccountController(IUser user)
        {
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

        public IActionResult UpdateProfile()
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

            return View(user);
        }

        [HttpPost]
        public IActionResult UpdateProfile(User user)
        {
            if (!ModelState.IsValid)
            {
                return View(user);
            }

            try
            {
                var existingUser = _user.GetUserByUsername(user.Username);
                if (existingUser != null)
                {
                    existingUser.Email = user.Email;
                    existingUser.Contact = user.Contact;

                    _user.UpdateProfile(existingUser);

                    ViewBag.Message = "Profile updated successfully!";
                    return RedirectToAction("Index", "Home"); // Redirect ke halaman Home Index
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

            return View(user);
        }

    }
}
