using Mapster;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MySolution.WebApi.Data;
using MySolution.WebApi.Endpoints;
using MySolution.WebApi.Extensions;
using MySolution.WebApi.Extensions.OpenApi;
using MySolution.WebApi.Libraries.CacheProvider;
using MySolution.WebApi.Libraries.Globalizer;
using MySolution.WebApi.Libraries.JwtTokenProvider;
using MySolution.WebApi.Libraries.MessageSender.Email;
using MySolution.WebApi.Libraries.MessageSender.Sms;
using MySolution.WebApi.Libraries.Validator;
using MySolution.WebApi.Libraries.ViewRenderer;
using MySolution.WebApi.Options;
using Scalar.AspNetCore;
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

builder.Services.AddDbContext<DefaultDbContext>((serviceProvider, options) =>
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

    options.UseNpgsql(connectionString, npgsqlOptions =>
    {
        npgsqlOptions.CommandTimeout(30);
        npgsqlOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorCodesToAdd: null);
        npgsqlOptions.MigrationsAssembly(typeof(Program).Assembly.GetName().Name);
    });

    if (builder.Environment.IsDevelopment())
    {
        options.EnableSensitiveDataLogging();
        options.EnableDetailedErrors();
    }
});

builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
});
builder.Services.AddMapster();
builder.Services.AddGlobalizer();
builder.Services.AddValidators();
builder.Services.AddViewRenderer();
builder.Services.AddMemoryCacheProvider();

builder.Services.AddRepositories();
builder.Services.AddServices();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
    .AddJwtTokenProvider(options => builder.Configuration.Bind("Authentication:Jwt", options))
    .AddGoogle(options => builder.Configuration.Bind("Authentication:Google", options))
    .AddExternalCookie();

builder.Services.AddEmailProvider(options => builder.Configuration.Bind("Messaging:Email", options))
                .AddSmsSender(options => builder.Configuration.Bind("Messaging:Sms", options));

builder.Services.AddAuthorization();

builder.Services.Configure<AllowedOriginsOptions>(builder.Configuration);
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        var options = builder.Configuration.Get<AllowedOriginsOptions>()
            ?? throw new InvalidOperationException("AllowedOrigins configuration not found.");

        if (options.AllowAnyOrigin)
            policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
        else
            policy.WithOrigins(options.GetOrigins()).AllowAnyHeader().AllowAnyMethod().AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options => options
        .AddPreferredSecuritySchemes(JwtBearerDefaults.AuthenticationScheme)
        .AddHttpAuthentication(JwtBearerDefaults.AuthenticationScheme, auth =>
        {
            auth.Token = string.Empty;
        }));
}

app.UseHttpsRedirection();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

await app.RunDbMigrationsAsync<DefaultDbContext>();

app.MapAccount();

await app.RunAsync();