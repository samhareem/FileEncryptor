using System;
using System.Data;
using System.IO;
using System.Security.Cryptography;

namespace FileEncryptor.Encryption
{
    /// <summary>
    /// Encodes and decodes a file with a given password using the AES-algorithm.
    /// </summary>
    public class BaseSymmetricEncryptor : ISymmetricEncryptor
    {
        private readonly SymmetricAlgorithm _algorithm;
        private readonly int _chunkSize;
        private readonly int _saltSize;

        public BaseSymmetricEncryptor()
        {
            _algorithm = Aes.Create();
            _chunkSize = _algorithm.BlockSize;
            _saltSize = 16;
        }
        
        /// <summary>
        /// Encrypts input file to output file using given password.
        /// </summary>
        /// <param name="input">Input file.</param>
        /// <param name="output">Output file.</param>
        /// <param name="password">Password.</param>
        public void EncryptFile(FileInfo input, FileInfo output, string password, bool overwrite = false)
        {
            if (!CheckInputFile(input))
            {
                throw new FileNotFoundException("Input file not found.");
            }

            if (!CheckOutputFile(output, overwrite))
            {
                throw new ConstraintException("Output file exists and overwrite flag has not been set.");
            }

            var keyDerivator = new BaseKeyDerivator(password, _saltSize);
            
            using var outputStream = output.Open(FileMode.Create);
            
            //Fetch key and salt from keyDerivator, set key for algorithm and write salt to stream
            var key = keyDerivator.DeriveKey(_algorithm.KeySize / 8);
            _algorithm.Key = key;
            var salt = keyDerivator.GetSalt();
            outputStream.Write(salt);
            
            //Fetch initialization vector from algorithm and write it to stream
            var iv = _algorithm.IV;
            outputStream.Write(iv);
            
            using var encryptionStream =
                new CryptoStream(outputStream, _algorithm.CreateEncryptor(), CryptoStreamMode.Write);

            //Initialize bytesRead to 1 for read-write loop
            var bytesRead = 1;
            var buffer = new byte[_chunkSize];
            
            using var inputStream = input.Open(FileMode.Open);
            while (bytesRead > 0) 
            {
                bytesRead = inputStream.Read(buffer, 0, _chunkSize);
                encryptionStream.Write(buffer, 0, bytesRead);
            }
            
            inputStream.Dispose();
            encryptionStream.Dispose();
        }
        
        /// <summary>
        /// Decrypts input file to output file using given password.
        /// </summary>
        /// <param name="input">Input file.</param>
        /// <param name="output">Output file.</param>
        /// <param name="password">Password.</param>
        public void DecryptFile(FileInfo input, FileInfo output, string password, bool overwrite = false)
        {
            if (!CheckInputFile(input))
            {
                throw new FileNotFoundException("Input file not found.");
            }

            if (!CheckOutputFile(output, overwrite))
            {
                throw new ConstraintException("Output file exists and overwrite flag has not been set.");
            }
            
            if (String.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Null or empty password provided for decryption operation.");
            }
            
            using var inputStream = input.Open(FileMode.Open);
            
            //Fetch salt from input file, use it to derive key from given password and set it for the decryption algorithm
            var salt = new byte[_saltSize];
            inputStream.Read(salt, 0, _saltSize);
            var keyDerivator = new BaseKeyDerivator(password, salt);
            _algorithm.Key = keyDerivator.DeriveKey(_algorithm.KeySize / 8);

            //Fetch initialization vector from input file and set it for the algorithm
            var ivSize = _chunkSize / 8;
            var iv = new byte[ivSize];
            inputStream.Read(iv, 0, ivSize);
            _algorithm.IV = iv;
            
            using var decryptionStream =
                new CryptoStream(inputStream, _algorithm.CreateDecryptor(), CryptoStreamMode.Read);

            //Initialize bytesRead to 1 for read-write loop
            var bytesRead = 1;
            var buffer = new byte[_chunkSize];
            
            using var outputStream = output.Open(FileMode.Create);
            while (bytesRead > 0)
            {
                bytesRead = decryptionStream.Read(buffer, 0, _chunkSize);
                outputStream.Write(buffer, 0, bytesRead);
            }
            
            decryptionStream.Dispose();
            outputStream.Dispose();
        }
        
        //For now we only check that the file exists, but additional checks can be easily added
        private bool CheckInputFile(FileInfo input)
        {
            return input.Exists;
        }
        
        //For now we only check that overwriting is enabled if output file exists, but additional checks cam be easily added
        private bool CheckOutputFile(FileInfo output, bool overwrite)
        {
            if (output.Exists && !overwrite)
            {
                return false;
            }

            return true;
        }
    }
}