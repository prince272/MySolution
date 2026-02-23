using Mapster;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using MySolution.WebApi.Data;
using MySolution.WebApi.Endpoints;
using MySolution.WebApi.Extensions;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.JwtToken;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Services.Identity;
using Scalar.AspNetCore;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.DictionaryKeyPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;

    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));

    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.Never;
});

builder.Services.AddSingleton(TimeProvider.System);

// Add services to the container.
builder.Services.AddDbContext<DefaultDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddOpenApi();
builder.Services.AddMapster();
builder.Services.AddGlobalizer();
builder.Services.AddValidators();
builder.Services.AddRepositories();
builder.Services.AddServices();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwt(options => builder.Configuration.Bind("Jwt", options));

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

await app.RunDbMigrationsAsync<DefaultDbContext>();

app.MapIdentity();

// Protected endpoint example
app.MapGet("/me", (ClaimsPrincipal user) =>
{
    var userId = user.GetUserId();
    return Results.Ok(new { UserId = userId });
})
.RequireAuthorization();

await app.RunAsync();