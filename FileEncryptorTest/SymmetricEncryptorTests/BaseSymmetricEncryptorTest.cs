using System.IO;
using System.Security.Cryptography;
using FileEncryptor.Encryption;
using Xunit;

namespace FileEncryptorTest.SymmetricEncryptorTests
{
    public class BaseSymmetricEncryptorTest
    {
        private FileInfo _validInputFile = new FileInfo("../../../SymmetricEncryptorTests/Input.txt");
        private string _password = "testPassword";
        
        [Fact]
        public void Encrypt_InputFileNotFound_ThrowsException()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var nonExistantFile = new FileInfo("Input2.txt");
            var outputFile = new FileInfo("Output.txt");
            
            Assert.Throws<FileNotFoundException>(() => encryptor.EncryptFile(nonExistantFile, outputFile, _password));
        }
        
        [Fact]
        public void Encrypt_AllParametersValid_Ok()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var outputFile = new FileInfo("Output.txt");
            
            encryptor.EncryptFile(_validInputFile, outputFile, _password);
            
            Assert.True(outputFile.Exists);

            var inputFileContents = new byte[10];
            var inputFileStream = _validInputFile.OpenRead();
            inputFileStream.Read(inputFileContents, 0, 10);
            inputFileStream.Dispose();
            
            var outputFileContents = new byte[10];
            var outputFileStream = outputFile.OpenRead();
            outputFileStream.Read(outputFileContents, 0, 10);
            outputFileStream.Dispose();
            
            Assert.NotEqual(inputFileContents, outputFileContents);
            
            outputFile.Delete();
        }

        [Fact]
        public void Decrypt_InputFileNotFound_ThrowsException()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var nonExistantFile = new FileInfo("Output.txt");
            var outputFile = new FileInfo("Decrypt.txt");
            
            Assert.Throws<FileNotFoundException>(() => encryptor.EncryptFile(nonExistantFile, outputFile, _password));
        }

        [Fact]
        public void Decrypt_WrongPassword_ThrowsCryptographicException()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var outputFile = new FileInfo("Output.txt");
            var decryptedFile = new FileInfo("Decrypt.txt");
            
            encryptor.EncryptFile(_validInputFile, outputFile, _password);
            
            Assert.Throws<CryptographicException>(() => encryptor.DecryptFile(outputFile, decryptedFile, "wrongPassword"));
            
            outputFile.Delete();
        }
        
        [Fact]
        public void EncryptDecrypt_DecryptedFileEqualsOriginal_Ok()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var outputFile = new FileInfo("Output.txt");
            var decryptedFile = new FileInfo("Decrypt.txt");
            
            encryptor.EncryptFile(_validInputFile, outputFile, _password);
            encryptor.DecryptFile(outputFile, decryptedFile, _password);
            
            var inputFileContents = new byte[_validInputFile.Length];
            var inputFileStream = _validInputFile.OpenRead();
            inputFileStream.Read(inputFileContents, 0, (int) _validInputFile.Length);
            inputFileStream.Dispose();
            
            var decryptedFileContents = new byte[decryptedFile.Length];
            var decryptedFileStream = decryptedFile.OpenRead();
            decryptedFileStream.Read(decryptedFileContents, 0, (int) decryptedFile.Length);
            decryptedFileStream.Dispose();
            
            Assert.Equal(inputFileContents, decryptedFileContents);
            
            outputFile.Delete();
            decryptedFile.Delete();
        }
    }
}