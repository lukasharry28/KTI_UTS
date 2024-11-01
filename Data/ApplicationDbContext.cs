using System;
using Microsoft.EntityFrameworkCore;
using A07_UTS.Models;

namespace A07_UTS.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext>options) : base(options)
    {

    }

    public DbSet<Student> Students { get; set; } = null!;

    public DbSet<User> Users { get; set; } = null!;

}
