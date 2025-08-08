using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using HmacVerificationApi.Models;
using HmacVerificationApi.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace HmacVerificationApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VerificationController : ControllerBase
    {
        private readonly ILogger<VerificationController> _logger;
        private readonly HmacVerificationService _hmacVerificationService;

        public VerificationController(
            ILogger<VerificationController> logger,
            HmacVerificationService hmacVerificationService)
        {
            _logger = logger;
            _hmacVerificationService = hmacVerificationService;
        }

        [HttpPost]
        public async Task<IActionResult> VerifyPayload()
        {
            try
            {
                // Get the X-Server-Signature header
                if (!Request.Headers.TryGetValue("X-Server-Signature", out var digestHeader))
                {
                    return BadRequest("Missing X-Server-Signature header");
                }

                string digest = digestHeader.ToString();
                
                // Read the request body
                Request.EnableBuffering();
                using var reader = new StreamReader(
                    Request.Body,
                    encoding: Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    leaveOpen: true);
                
                string rawBody = await reader.ReadToEndAsync();
                
                // Reset the request body position
                Request.Body.Position = 0;
                
                // Verify the HMAC signature
                bool isValid = _hmacVerificationService.VerifyHmacSignature(rawBody, digest);
                
                if (!isValid)
                {
                    _logger.LogWarning("Invalid HMAC signature provided");
                    return Unauthorized("Invalid signature");
                }
                
                // Process the payload
                // You can deserialize it here if needed
                // var payload = JsonSerializer.Deserialize<PayloadModel>(rawBody);
                _logger.LogInformation("HMAC signature verified successfully");
                return Ok(new { 
                    Success = true, 
                    Message = "Signature verified successfully" 
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying payload");
                return StatusCode(500, "An error occurred while processing the request");
            }
        }
    }
}