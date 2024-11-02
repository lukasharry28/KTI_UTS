using System;
using A07_UTS.Models;

namespace A07_UTS.Data;

public interface IUser
{
    User Registration(User user);
    User Login(User user);
    User GetUserByUsername(string username);
    void UpdatePassword(User user);

    void UpdateProfile(User user);

    void ForgotPassword(string user);
    void ResetPassword(User user);

    void SaveOTP(string username, string otp);
    bool ValidateOTP(string username, string otp);
    
}
