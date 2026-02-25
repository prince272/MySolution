using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MySolution.WebApi.Data.Migrations
{
    /// <inheritdoc />
    public partial class RemoveSchemeFromJwtToken : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Scheme",
                table: "JwtTokens");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Scheme",
                table: "JwtTokens",
                type: "text",
                nullable: false,
                defaultValue: "");
        }
    }
}
