using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using FileEncryptor.Encryption;

namespace FileEncryptor
{
    static class Program
    {
        private static ISymmetricEncryptor _encryptor;
        private static IPasswordGenerator _generator;
        
        static void Main(string[] args)
        {
            _encryptor = new BaseSymmetricEncryptor();
            _generator = new BasePasswordGenerator();

            var rootCommand = CreateRootCommand();

            rootCommand.Invoke(args);
        }

        private static RootCommand CreateRootCommand()
        {
            var rootCommand = new RootCommand
            {
                new Argument<Operation>("Operation",
                    "Specify the operation to execute"),
                new Argument<FileInfo>(
                    "Input",
                    "Specify input file").LegalFilePathsOnly(),
                new Argument<FileInfo>(
                    "Output",
                    "Specify output file").LegalFilePathsOnly(),
                new Option<string>(
                    "--password",
                    () => "",
                    "Specify key to be used for decoding"),
                new Option<bool>(
                    "--overwrite",
                    () => false,
                    "Specify whether output file should be overwritten if it exists")
            };

            rootCommand.Description = "Console app to encrypt and decrypt files.";

            rootCommand.Handler = CommandHandler.Create<Operation, FileInfo, FileInfo, string, bool>(
                (operation, input, output, password, overwrite) =>
                {
                    switch (operation)
                    {
                        case Operation.Encrypt:
                            if (String.IsNullOrWhiteSpace(password))
                            {
                                password = _generator.Generate(32);
                                Console.WriteLine($"Encoding file with generated password: {password}");
                            }

                            try
                            {
                                _encryptor.EncryptFile(input, output, password, overwrite);
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("Encryption failed with following exception:");
                                Console.WriteLine(e.GetType() + " - " + e.Message);
                            }
                            
                            break;
                        case Operation.Decrypt:
                            try
                            {
                                _encryptor.DecryptFile(input, output, password, overwrite);
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("Encryption failed with following exception:");
                                Console.WriteLine(e.GetType() + " - " + e.Message);
                            }
                            break;
                    }
                });
            return rootCommand;
        }

        private enum Operation
        {
            Encrypt,
            Decrypt
        };
    }
}