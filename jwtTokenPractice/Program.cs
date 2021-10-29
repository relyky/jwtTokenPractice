using Jose;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace jwtTokenPractice
{
    class Program
    {
        static void Main(string[] args)
        {
            var key = new byte[] { 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 117, 37, 158 };
            Guid regCode = new Guid(key);
            string mobNo = "0955123456";
            string token = WrapToken(mobNo, regCode);

            Console.WriteLine($"token: {token}");

            bool isValid = VerifyToken(token, mobNo, regCode);
            Console.WriteLine($"isValid: {isValid}");

            Console.WriteLine($"isValid: {VerifyToken(token, "09551234x", regCode)}");
            Console.WriteLine($"isValid: {VerifyToken(token, mobNo, Guid.NewGuid())}");
            Console.WriteLine($"isValid: {VerifyToken("xxx", mobNo, regCode)}");

            Console.WriteLine("Press any key to continue.");
            Console.ReadKey();
        }

        private static string WrapToken(string mobileNo, Guid regCode)
        {
            var payload = new Dictionary<string, object>()
            {
                { "mobNo", mobileNo },
                { "regCode", regCode },
                { "issTime", DateTime.UtcNow }
            };

            var key = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };
            return JWT.Encode(payload, key, JweAlgorithm.A256GCMKW, JweEncryption.A256CBC_HS512);
        }

        private static bool VerifyToken(string msg, string mobileNo, Guid regCode)
        {
            try
            {
                var key = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };
                var decoded = JWT.Decode<Dictionary<string, object>>(msg, key);
                bool issTime = decoded["issTime"] is DateTime;
                return issTime && decoded["mobNo"].Equals(mobileNo) && regCode.Equals(new Guid((string)decoded["regCode"]));
            }
            catch
            {
                return false;
            }
        }
    }
}