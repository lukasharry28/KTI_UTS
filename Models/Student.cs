using System;
using System.ComponentModel.DataAnnotations;

namespace A07_UTS.Models;

public class Student
{
    [Key]
    public string nim { get; set; } = null!;

    public string name { get; set; } = null!;

    public int usia { get; set; }

}
