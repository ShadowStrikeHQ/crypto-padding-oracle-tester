# crypto-padding-oracle-tester
A tool to test a web server or cryptographic implementation for padding oracle vulnerabilities in CBC mode encryption. Sends crafted ciphertext to the server and analyzes the response to identify vulnerabilities. Relies on the `requests` library for HTTP interaction. - Focused on Basic cryptographic operations

## Install
`git clone https://github.com/ShadowStrikeHQ/crypto-padding-oracle-tester`

## Usage
`./crypto-padding-oracle-tester [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: The URL to test for the padding oracle vulnerability.
- `-d`: No description provided
- `-c`: No description provided
- `-k`: No description provided
- `-iv`: No description provided
- `-p`: No description provided
- `-e`: No description provided
- `--block_size`: No description provided
- `--get`: Use GET request instead of POST.
- `--test_mode`: Enable test mode to not send any requests to the server

## License
Copyright (c) ShadowStrikeHQ
