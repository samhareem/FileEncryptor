# FileEncryptor

Simple command line tool to allow encryption and decryption of files. Currently only supports symmetrical encryption with a password.

##TODO

- Add more encryption algorithms to the tool and allow the user to choose which algorithm to use.
- Add a configuration file and replace hardcoded defaults with configured variables.
- Add a configuration analysis tool which will evaluate the configuration file and warn the user if any values are insecure, such as as default salt length being too low.
