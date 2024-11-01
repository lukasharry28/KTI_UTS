using System;
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
        {
            throw new Exception("Username not found");
        }

        Console.WriteLine($"[Login] Hash dari database: {_user.Password}"); // Logging hash dari database
        Console.WriteLine($"[Login] Password yang diinput: {user.Password}"); // Logging password yang diinput

        if (!BCrypt.Net.BCrypt.Verify(user.Password, _user.Password))
        {
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
}