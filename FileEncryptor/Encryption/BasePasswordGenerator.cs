using System;
using System.Security.Cryptography;

namespace FileEncryptor.Encryption
{
    /// <summary>
    /// Generates a string password by generating a cryptographically secure array of random bytes and encoding them
    /// to a base 64 string.
    /// </summary>
    public class BasePasswordGenerator : IPasswordGenerator
    {
        private readonly RandomNumberGenerator _rng;
        
        /// <summary>
        /// Initialize a new instances of BasePasswordGenerator.
        /// </summary>
        public BasePasswordGenerator()
        {
            _rng = RandomNumberGenerator.Create();
        }
        
        /// <summary>
        /// Generates a password of given byte length.
        /// </summary>
        /// <param name="length">Length of the password in bytes.</param>
        /// <returns>A base 64 encoded password.</returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public string Generate(int length)
        {
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be greater than zero.");
            }
            var bytes = new byte[length];
            _rng.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }
    }
}