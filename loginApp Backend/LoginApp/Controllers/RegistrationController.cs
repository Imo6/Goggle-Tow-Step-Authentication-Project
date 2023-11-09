
using Google.Authenticator;
using LoginApp.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Data;
using System.Data.SqlClient;

namespace LoginApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RegistrationController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public RegistrationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // Handle registration of a user
        [HttpPost]
        [Route("Registration")]
        public string registration(Registration registration)
        {
            // Create a SQL connection using the connection string from configuration
            SqlConnection con = new SqlConnection(_configuration.GetConnectionString("conn").ToString());

            // Define a SQL command for inserting registration data
            SqlCommand cmd = new SqlCommand("INSERT INTO Registration (Username, Password) VALUES (@Username, @Password)", con);

            // Add parameters to the SQL command
            cmd.Parameters.AddWithValue("@Username", registration.Username);
            cmd.Parameters.AddWithValue("@Password", registration.Password);

            // Open the database connection
            con.Open();

            // Execute the SQL command and get the number of affected rows
            int i = cmd.ExecuteNonQuery();

            // Close the database connection
            con.Close();

            // Check if data was inserted successfully
            if (i > 0)
            {
                return "Data Inserted";
            }
            else
            {
                return "Error";
            }
        }

        // Handle user login
        [HttpPost]
        [Route("login")]
        public string login(Registration registration)
        {
            // Check if the username or password is empty
            if (string.IsNullOrEmpty(registration.Username) || string.IsNullOrEmpty(registration.Password))
            {
                return "Invalid User";
            }

            // Create a SQL connection using the connection string from configuration
            SqlConnection con = new SqlConnection(_configuration.GetConnectionString("conn").ToString());

            // Define a SQL command for selecting a user by username and password
            SqlCommand cmd = new SqlCommand("SELECT * FROM Registration WHERE Username = @Username AND Password = @Password", con);

            // Add parameters to the SQL command
            cmd.Parameters.AddWithValue("@Username", registration.Username);
            cmd.Parameters.AddWithValue("@Password", registration.Password);

            // Create a DataTable to hold the query result
            DataTable dt = new DataTable();

            // Create a data adapter to fill the DataTable
            SqlDataAdapter da = new SqlDataAdapter(cmd);
            da.Fill(dt);

            // Check if there are any rows in the DataTable (user found)
            if (dt.Rows.Count > 0)
            {
                return "Valid User";
            }
            else
            {
                return "Invalid User";
            }
        }

        // Generate a Google Authenticator token setup QR code
        [HttpGet]
        [Route("generatetoken")]
        public string GenerateToken()
        {
            // Get the Google Authenticator key from configuration
            string googleAuthKey = _configuration.GetValue<string>("appSettings:GoogleAuthKey");

            // Create a TwoFactorAuthenticator instance
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();

            // Generate a QR code setup for Google Authenticator
            var setupInfo = tfa.GenerateSetupCode("Google Authenticator", "2FA", googleAuthKey, true, 5); // the width and height of the QR Code in pixels

            // Get the QR code image URL
            string qrCodeImageUrl = setupInfo.QrCodeSetupImageUrl;

            // Return the URL to display the QR code
            return qrCodeImageUrl;
        }

        // Validate a Google Authenticator PIN
        [HttpPost]
        [Route("validate")]
        public async Task<string> Validate()
        {
            // Get the Google Authenticator key from configuration
            string googleAuthKey = _configuration.GetValue<string>("appSettings:GoogleAuthKey");

            // Read the request body as a string
            using (StreamReader reader = new StreamReader(Request.Body))
            {
                string val = await reader.ReadToEndAsync();

                // Deserialize the JSON input into a PinClass object
                var result = JsonConvert.DeserializeObject<PinClass>(val);

                // Create a TwoFactorAuthenticator instance
                TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();

                // Validate the PIN
                bool isCorrectPIN = tfa.ValidateTwoFactorPIN(googleAuthKey, result.pin, true);

                // Return the validation result
                if (isCorrectPIN)
                {
                    return "Success";
                }
                else
                {
                    return "Authentication Unsuccessful";
                }
            }
        }

        // Define a class to represent the PIN input
        public class PinClass
        {
            public string pin { get; set; }
        }
    }
}
