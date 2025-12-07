using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AspNetCoreExtensions.Keycloak.Db.Migrations
{
    /// <inheritdoc />
    public partial class UserSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "user_sessions",
                columns: table => new
                {
                    sid = table.Column<Guid>(type: "uuid", nullable: false),
                    principal = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: false),
                    authentication_scheme = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    properties = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_sessions", x => x.sid);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "user_sessions");
        }
    }
}
