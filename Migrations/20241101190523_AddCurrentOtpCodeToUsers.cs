using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace A07_UTS.Migrations
{
    /// <inheritdoc />
    public partial class AddCurrentOtpCodeToUsers : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CurrentOtpCode",
                table: "Users",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "OtpExpiration",
                table: "Users",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CurrentOtpCode",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "OtpExpiration",
                table: "Users");
        }
    }
}
