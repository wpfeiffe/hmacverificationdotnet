
using HmacVerificationApi.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Register HMAC verification service with a secret key
// In production, store this in a secure configuration and not in code

var secretKey = builder.Configuration["HMACVERIFICATION_SECRET"];

if (string.IsNullOrEmpty(secretKey))
{
    throw new InvalidOperationException("HMACVERIFICATION_SECRET environment variable is not set.");
}

builder.Services.AddSingleton<HmacVerificationService>(new HmacVerificationService(secretKey));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapControllers();

app.Run();