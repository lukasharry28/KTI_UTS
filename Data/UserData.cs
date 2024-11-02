using System;
using System.Net.Mail;
using A07_UTS.Models;

namespace A07_UTS.Data;

public class UserData : IUser
{
    private readonly ApplicationDbContext _db;

    public UserData(ApplicationDbContext db)
    {
        _db = db;
    }

    public User GetUserByUsername(string username)
    {
        var user = _db.Users.FirstOrDefault(u => u.Username == username);

        if (user == null)
        {
            throw new Exception("User not found");
        }
        return user;
    }

    public User Login(User user)
    {
        var _user = _db.Users.FirstOrDefault(u => u.Username == user.Username);
            if (_user == null)
                throw new Exception("Username not found");
        
        Console.WriteLine($"[Login] Hash dari database: {_user.Password}"); // Logging hash dari database
        Console.WriteLine($"[Login] Password yang diinput: {user.Password}"); // Logging password yang diinput

        if (_user.FailedLoginAttempts >= 5 && _user.LockoutEndTime > DateTime.UtcNow)
            throw new Exception("Account locked. Try again later.");

        if (BCrypt.Net.BCrypt.Verify(user.Password, _user.Password))
        {
            _user.FailedLoginAttempts = 0; // Reset on successful login
            _db.SaveChanges();
        }
        else
        {
            _user.FailedLoginAttempts++;
            if (_user.FailedLoginAttempts >= 5)
            {
                _user.LockoutEndTime = DateTime.UtcNow.AddMinutes(15); // Lock for 15 minutes
            }
            _db.SaveChanges();
            Console.WriteLine("[Login] Password tidak cocok"); // Logging jika verifikasi gagal
            throw new Exception("Password is incorrect");
        }
        Console.WriteLine("[Login] Password cocok"); // Logging jika verifikasi berhasil
        return _user;
    }

    public User Registration(User user)
    {
        try
        {
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            Console.WriteLine($"[Registrasi] Password hash yang disimpan: {user.Password}"); // Logging hash
            _db.Users.Add(user);
            _db.SaveChanges();
            return user;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public void UpdatePassword(User user)
    {
        var existingUser = _db.Users.FirstOrDefault(u => u.Username == user.Username);
        if (existingUser != null)
        {
            existingUser.Password = user.Password;
            _db.SaveChanges();
        }
    }

    public void UpdateProfile(User user)
    {
        var existingUser = _db.Users.FirstOrDefault(u => u.Username == user.Username);
        if (existingUser != null)
        {
            existingUser.Username = user.Username;
            existingUser.Email = user.Email;
            existingUser.Contact = user.Contact;
            _db.SaveChanges();
        }
    }

    public void ForgotPassword(string usernameOrEmail)
        {
            var user = _db.Users.FirstOrDefault(u => u.Username == usernameOrEmail || u.Email == usernameOrEmail);
            if (user == null)
            {
                throw new Exception("User not found.");
            }

            string otp = GenerateOtp();
            SaveOTP(user.Username, otp);
            SendOtpEmail(user.Email, otp);
        }

    private string GenerateOtp()
    {
        // Metode untuk menghasilkan kode OTP, bisa menggunakan random number generator atau algoritma lainnya
        return new Random().Next(100000, 999999).ToString(); // Contoh menghasilkan OTP 6 digit
    }

    private void SendOtpEmail(string email, string otp)
    {
        using (var client = new SmtpClient("smtp.your-email-provider.com"))
        {
            var mailMessage = new MailMessage("your-email@example.com", email)
            {
                Subject = "Your OTP Code",
                Body = $"Your OTP code for resetting your password is: {otp}"
            };
            client.Send(mailMessage);
        }
    }

    public void ResetPassword(User user)
    {
        var existingUser = _db.Users.FirstOrDefault(u => u.Username == user.Username);
        if (existingUser != null)
        {
            existingUser.Password = user.Password;
            _db.SaveChanges();
        }
    }

    public void SaveOTP(string username, string otp)
    {
        var user = GetUserByUsername(username);
        user.CurrentOtpCode = otp;
        user.OtpExpiration = DateTime.UtcNow.AddMinutes(5);
        _db.SaveChanges();
    }

    public bool ValidateOTP(string username, string otp)
    {
        var user = GetUserByUsername(username);
        return user.CurrentOtpCode == otp && user.OtpExpiration > DateTime.UtcNow;
    }


}