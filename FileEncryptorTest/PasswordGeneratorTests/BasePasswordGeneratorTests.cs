using System;
using FileEncryptor.Encryption;
using Xunit;

namespace FileEncryptorTest.PasswordGeneratorTests
{
    public class BasePasswordGeneratorTest
    {
        [Theory]
        [InlineData(48)]
        [InlineData(24)]
        [InlineData(12)]
        public void Generate_PositiveInteger_Ok(int length)
        {
            var generator = new BasePasswordGenerator();
            var password = generator.Generate(length);
            Assert.Equal(Convert.FromBase64String(password).Length, length);
        }
        
        [Theory]
        [InlineData(-48)]
        [InlineData(-24)]
        [InlineData(0)]
        public void Generate_NegativeOrZeroInteger_ThrowsArgumentOutOfRangeException(int length)
        {
            var generator = new BasePasswordGenerator();
            Assert.Throws<ArgumentOutOfRangeException>(() => generator.Generate(length));
        }
    }
}