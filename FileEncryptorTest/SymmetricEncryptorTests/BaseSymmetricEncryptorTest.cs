using System.IO;
using System.Security.Cryptography;
using FileEncryptor.Encryption;
using Xunit;

namespace FileEncryptorTest.SymmetricEncryptorTests
{
    public class BaseSymmetricEncryptorTest
    {
        private FileInfo _validInputFile = new FileInfo("../../../SymmetricEncryptorTests/Input.txt");
        private FileInfo _validOutputFile = new FileInfo("../../../SymmetricEncryptorTests/Output.txt");
        private string _password = "testPassword";
        
        [Fact]
        public void Encrypt_InputFileNotFound_ThrowsException()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var nonExistantFile = new FileInfo("Input2.txt");

            Assert.Throws<FileNotFoundException>(() => encryptor.EncryptFile(nonExistantFile, _validOutputFile, _password));
        }
        
        [Fact]
        public void Encrypt_AllParametersValid_Ok()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var outputFile = new FileInfo("Output.txt");
            
            encryptor.EncryptFile(_validInputFile, outputFile, _password, true);
            
            outputFile.Refresh();
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
            var nonExistantFile = new FileInfo("Output2.txt");
            var outputFile = new FileInfo("TempDecrypt.txt");
            
            Assert.Throws<FileNotFoundException>(() => encryptor.EncryptFile(nonExistantFile, outputFile, _password));
            
            outputFile.Delete();
        }

        [Fact]
        public void Decrypt_WrongPassword_ThrowsCryptographicException()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var decryptedFile = new FileInfo("TempDecrypt2.txt");

            Assert.Throws<CryptographicException>(() => encryptor.DecryptFile(_validOutputFile, decryptedFile, "wrongPassword", true));
            
            decryptedFile.Delete();
        }
        
        [Fact]
        public void EncryptDecrypt_DecryptedFileEqualsOriginal_Ok()
        {
            var encryptor = new BaseSymmetricEncryptor();
            var decryptedFile = new FileInfo("TempDecrypt3.txt");
            
            encryptor.EncryptFile(_validInputFile, _validOutputFile, _password, true);
            encryptor.DecryptFile(_validOutputFile, decryptedFile, _password, true);
            
            var inputFileContents = new byte[_validInputFile.Length];
            var inputFileStream = _validInputFile.OpenRead();
            inputFileStream.Read(inputFileContents, 0, (int) _validInputFile.Length);
            inputFileStream.Dispose();
            
            decryptedFile.Refresh();
            var decryptedFileContents = new byte[decryptedFile.Length];
            var decryptedFileStream = decryptedFile.OpenRead();
            decryptedFileStream.Read(decryptedFileContents, 0, (int) decryptedFile.Length);
            decryptedFileStream.Dispose();
            
            Assert.Equal(inputFileContents, decryptedFileContents);
            
            decryptedFile.Delete();
        }
    }
}