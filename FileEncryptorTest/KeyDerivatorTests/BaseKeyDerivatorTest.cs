using System;
using FileEncryptor.Encryption;
using Xunit;

namespace FileEncryptorTest.KeyDerivatorTests
{
    public class BaseKeyDerivatorTest
    {
        private string _password = "testPassword";
        private int _defaultSaltSize = 16;
        
        [Theory]
        [InlineData(7)]
        [InlineData(4)]
        [InlineData(0)]
        public void Initialization_SaltLengthLessThan8Bytes_ThrowsArgumentException(int length)
        {
            Assert.Throws<ArgumentException>(() => new BaseKeyDerivator(_password, length));
        }
        
        [Theory]
        [InlineData(new byte[] {123, 14, 9, 12, 5, 123, 11})]
        [InlineData(new byte[] {1, 144, 92, 12, 5, 123, 11})]
        [InlineData(new byte[] {13, 42, 182, 12, 5, 123, 11})]
        public void GetSalt_SaltLessThan8Bytes_ThrowsArgumentException(byte[] salt)
        {
            Assert.Throws<ArgumentException>(() => new BaseKeyDerivator(_password, salt));
        }
        
        [Theory]
        [InlineData(512)]
        [InlineData(256)]
        [InlineData(128)]
        public void DeriveKey_ReturnsGivenLength(int length)
        {
            var derivator = new BaseKeyDerivator(_password, _defaultSaltSize);
            var bytes = derivator.DeriveKey(length);
            Assert.Equal(bytes.Length, length);
        }
        
        [Theory]
        [InlineData(-512)]
        [InlineData(-256)]
        [InlineData(0)]
        public void DeriveKey_NegativeOrZeroLength_ThrowsArgumentOutOfRangeException(int length)
        {
            var derivator = new BaseKeyDerivator(_password, _defaultSaltSize);
            Assert.Throws<ArgumentOutOfRangeException>(() => derivator.DeriveKey(length));
        }

        [Theory]
        [InlineData(32)]
        [InlineData(16)]
        [InlineData(8)]
        public void GetSalt_ReturnsSaltOfCorrectLength(int length)
        {
            var derivator = new BaseKeyDerivator(_password, length);
            var bytes = derivator.GetSalt();
            Assert.Equal(bytes.Length, length);
        }
        
        [Theory]
        [InlineData(new byte[] {123, 14, 9, 12, 5, 123, 11, 11, 4})]
        [InlineData(new byte[] {1, 144, 92, 12, 5, 123, 11, 11, 4})]
        [InlineData(new byte[] {13, 42, 182, 12, 5, 123, 11, 11, 4})]
        public void GetSalt_ReturnsGivenSalt(byte[] salt)
        {
            var derivator = new BaseKeyDerivator(_password, salt);
            var bytes = derivator.GetSalt();
            Assert.Equal(bytes, salt);
        }
    }
}