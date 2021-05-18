namespace FileEncryptor.Encryption
{
    public interface IPasswordGenerator
    {
        public string Generate(int length);
    }
}