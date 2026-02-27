using Mapster;
using Microsoft.AspNetCore.Authentication.JwtBearer;
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
using MySolution.WebApi.Services.Accounts;
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

builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
});
builder.Services.AddMapster();
builder.Services.AddGlobalizer();
builder.Services.AddValidators();
builder.Services.AddViewRenderer();
builder.Services.AddMemoyCacheProvider();

builder.Services.AddRepositories();
builder.Services.AddServices();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtTokenProvider(options => builder.Configuration.Bind("Authentication:Jwt", options));

builder.Services.AddEmailProvider(options => builder.Configuration.Bind("Messaging:Email", options))
                .AddSmsSender(options => builder.Configuration.Bind("Messaging:Sms", options));

builder.Services.AddAuthorization();

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

app.UseAuthentication();
app.UseAuthorization();

await app.RunDbMigrationsAsync<DefaultDbContext>();

app.MapAccount();

await app.RunAsync();