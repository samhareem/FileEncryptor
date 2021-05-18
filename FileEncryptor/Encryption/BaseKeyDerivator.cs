using System.Security.Cryptography;

namespace FileEncryptor.Encryption
{
    /// <summary>
    /// Derives pseudo-random byte array key for a given password and salt.
    /// </summary>
    public class BaseKeyDerivator : IKeyDerivator
    {
        private Rfc2898DeriveBytes _keyDerivator;

        /// <summary>
        /// Initializes BaseKeyDerivator with a given password and salt length.
        /// </summary>
        /// <param name="password">Password.</param>
        /// <param name="saltSize">Length of salt in bytes.</param>
        public BaseKeyDerivator(string password, int saltSize)
        {
            _keyDerivator = new Rfc2898DeriveBytes(password, saltSize);
        }
        
        /// <summary>
        /// Initializes BaseKeyDerivator with a given password and salt.
        /// </summary>
        /// <param name="password">Password.</param>
        /// <param name="salt">Salt.</param>
        public BaseKeyDerivator(string password, byte[] salt)
        {
            _keyDerivator = new Rfc2898DeriveBytes(password, salt);
        }
        
        /// <summary>
        /// Returns a byte array key of the requested size.
        /// </summary>
        /// <param name="keySize">Length of the requested key in bytes.</param>
        /// <returns>Byte array.</returns>
        public byte[] DeriveKey(int keySize)
        {
            return _keyDerivator.GetBytes(keySize);
        }
        
        /// <summary>
        /// Returns salt used with this instance of BaseKeyDerivator.
        /// </summary>
        /// <returns>Byte array.</returns>
        public byte[] GetSalt()
        {
            return _keyDerivator.Salt;
        }
    }
}