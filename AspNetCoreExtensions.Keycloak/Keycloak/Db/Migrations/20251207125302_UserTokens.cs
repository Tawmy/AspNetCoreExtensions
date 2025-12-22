using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AspNetCoreExtensions.Keycloak.Db.Migrations
{
    /// <inheritdoc />
    public partial class UserTokens : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "user_tokens",
                columns: table => new
                {
                    sub = table.Column<Guid>(type: "uuid", nullable: false),
                    access_token = table.Column<string>(type: "character varying(32768)", maxLength: 32768, nullable: false),
                    d_po_p_json_web_key = table.Column<string>(type: "character varying(32768)", maxLength: 32768, nullable: true),
                    expiration = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    scope = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    client_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    access_token_type = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    refresh_token = table.Column<string>(type: "character varying(32768)", maxLength: 32768, nullable: true),
                    identity_token = table.Column<string>(type: "character varying(32768)", maxLength: 32768, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_tokens", x => x.sub);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "user_tokens");
        }
    }
}
