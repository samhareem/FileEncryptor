namespace FileEncryptor.Encryption
{
    public interface IKeyDerivator
    {
        public byte[] DeriveKey(int keySize);
        
        public byte[] GetSalt();
    }
}