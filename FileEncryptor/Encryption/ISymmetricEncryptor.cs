using System.IO;

namespace FileEncryptor.Encryption
{
    public interface ISymmetricEncryptor
    {
        public void EncryptFile(FileInfo input, FileInfo output, string password);
        
        public void DecryptFile(FileInfo input, FileInfo output, string password);
    }
}