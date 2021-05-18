using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.IO;
using System.Linq;
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
                    if (!input.Exists)
                    {
                        Console.WriteLine("Input file does not exist.");
                        return;
                    }
                    
                    if (output.Exists && !overwrite)
                    {
                        Console.WriteLine("Output file exists and overwrite argument is not specified.");
                        return;
                    }

                    switch (operation)
                    {
                        case Operation.Encrypt:
                            if (String.IsNullOrWhiteSpace(password))
                            {
                                password = _generator.Generate(32);
                                Console.WriteLine($"Encoding file with generated password: {password}");
                            }
                            _encryptor.EncryptFile(input, output, password);
                            break;
                        case Operation.Decrypt:
                            if (String.IsNullOrWhiteSpace(password))
                            {
                                Console.WriteLine("Decrypt operation requires password to be supplied.");
                                return;
                            }

                            _encryptor.DecryptFile(input, output, password);
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(operation), operation, null);
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