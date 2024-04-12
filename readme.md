# Jumproxy
Jumproxy is a simple encrypted proxy server which can be used to protect servers, such as ssh servers, from mass spam attacks on open ports. By opening the server on a public port, any request which is not encrypted with the secret password will be dropped. 

## How it works

Jumproxy utilizes a encrypted stream reader/writer, which implements the `io.Reader` and `io.Writer` interfaces. The stream reader/writer is initialized with a secret password, which is used to encrypt and decrypt the data. A small 4 byte header is added to the beginning of the data, which contains the length of the encrypted data. This allows the reader to know how much data to read from the stream.

This approach allows streams to be encrypted/decrypted directly, without buffers. This is useful for proxy servers, as it allows the server to forward data directly from the client to the destination server, without storing the data in memory. It is also simpler to implement, since go provides an io.Copy function which can be used to easily forward data, calling on the specialized reader and writer interfaces.


## Running Jumproxy
To compile Jumproxy, you can use the following command:
```bash
go build jumproxy.go
```

Here are some examples of how to run Jumproxy:

Server:
```bash
./jumproxy -l 2222 -k pwdfile.txt localhost 22 # Forward connections from port 2222 to port 22, 22 can be any port
```

Client:
```bash
# ssh
ssh -o "ProxyCommand ./jumproxy -k pwdfile.txt localhost 2222" localhost
# echo
echo "hello world :)" | ./jumproxy -k pwdfile.txt localhost 2222
# file
cat readme.md | ./jumproxy -k pwdfile.txt localhost 2222
# any
./jumproxy -k pwdfile.txt localhost 2222
# type in your message
```

