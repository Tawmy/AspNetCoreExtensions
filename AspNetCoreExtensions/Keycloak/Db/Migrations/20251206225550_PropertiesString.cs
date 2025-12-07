using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AspNetCoreExtensions.Keycloak.Db.Migrations
{
    /// <inheritdoc />
    public partial class PropertiesString : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "properties",
                table: "user_sessions",
                type: "character varying(4096)",
                maxLength: 4096,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "jsonb",
                oldNullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "properties",
                table: "user_sessions",
                type: "jsonb",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(4096)",
                oldMaxLength: 4096,
                oldNullable: true);
        }
    }
}
