package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"net"
	"io"
	"log"
	"os"

	pbkdf2 "golang.org/x/crypto/pbkdf2"
)

const (
	SALT       = "THIS IS A VERY SECURE SALT. ZEBRA SMARTPHONE BANANA CLOWN"
)

type EncryptedStream struct {
	Source io.ReadWriteCloser // implements io.Reader, io.Writer, io.Closer
	Cipher cipher.AEAD
} 

// Write implements io.Writer.
func (self EncryptedStream) Write(byteStream []byte) (n int, err error) {
	// log.Println("writing - encrypted stream")

	// Number only used once
	nonce := make([]byte, self.Cipher.NonceSize())

	// reads exactly NonceSize random bytes into nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	encryptedByteStream := self.Cipher.Seal(nonce, nonce, byteStream, nil)
	n, writeErr := self.Source.Write(encryptedByteStream)

	if n > 0 {
		return len(byteStream), writeErr
	}

	return 0, io.EOF
}

func (self EncryptedStream) Read(byteStream []byte) (n int, err error) {
	// log.Println("reading - encrypted stream")

	// read from the source stream (no buffer)
	n, readErr := self.Source.Read(byteStream)
	if n <= 0 {
		return 0, readErr
	}
	// decrypt the bytestream
	ns := self.Cipher.NonceSize()
	nonce, encryptedStream := byteStream[:ns], byteStream[ns:n]

	decryptedStream, err := self.Cipher.Open(nil, nonce, encryptedStream, nil)
	if err != nil {
		log.Println(err)
		return len(decryptedStream), err
	}
	log.Print(string(decryptedStream))
	copy(byteStream, decryptedStream)
	return len(decryptedStream), nil
}

func (self EncryptedStream) Close() error {
	return self.Source.Close()
}

func main() {
	// go run jumproxy.go [-l listenport] -k pwdfile destination port
	listenport := flag.String("l", "", "listenport")
	pwdfile := flag.String("k", "", "pwdfile")
	flag.Parse()

	// check arg length
	if *pwdfile == "" || len(flag.Args()) != 2 {
		log.Fatal("Usage: jumproxy [-l listenport] -k pwdfile destination port")
	}

	// get destination port
	destination := flag.Args()[0]
	port := flag.Args()[1]

	aesCipher := generateCipher(generateKey(*pwdfile)) // generate aes cipher
	if *listenport == "" {
		client(aesCipher, destination, port)
	} else {
		server(aesCipher, *listenport, destination, port)
	}
}

func client(aesCipher cipher.AEAD, destination, port string) { // take in pwdfile, destination, port
		// create a connection to destination:port
		conn, err := net.Dial("tcp", destination+":"+port)
		if err != nil {
			log.Fatal(err)
		}

		// open a stream writer with the server connection
		streamWriter := EncryptedStream{
			Source: conn,
			Cipher: aesCipher,
		}

		stdInReader := io.ReadCloser(os.Stdin)
		stdErrWriter := io.WriteCloser(os.Stderr)

		// make a channel to track the connection
		done := make(chan bool)

		// read response from server
		go func () { // nonblocking recv from server -- get all responses from server
			n, err := io.Copy(stdErrWriter, streamWriter)
			done <- true
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(n)
		}()

		// send the encrypted bytestream to the server
		go func () {	
			n, err := io.Copy(streamWriter, stdInReader)
			done <- true
			if err != nil {
				log.Fatal(err)
			}
			log.Println(n)
		}()

	// wait until one of the connections closes
	<- done

	// close both connections
	streamWriter.Close() // when this connection handler exits, close the connection
	stdInReader.Close()
	stdErrWriter.Close()
}

func server(aesCipher cipher.AEAD, listenport, destination, port string) { // take in pwdfile, listenport
	// listen on listenport
	ln, err := net.Listen("tcp", ":"+listenport)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	// accept connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		streamReader := EncryptedStream{
			Source: conn,
			Cipher: aesCipher,
		}

		go handleConnection(streamReader, destination, port) // handle connection
	}
}

func handleConnection(streamReader EncryptedStream, destination, port string) {
	// create a two-way stream with destination:port
	dst, err := net.Dial("tcp", destination+":"+port)
	// none of these errors should be fatal, should just close the connection
	if err != nil {
		log.Println(err)
		return
	}

	// make a channel to track the connection
	done := make(chan bool)	

	go func () { // nonblcking recv from dst -- get all responses from dst
			n, err := io.Copy(streamReader, dst) 
			done <- true
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(n)
		}()

	go func () {
		// send decrypted bytes to destination:port
		_, err = io.Copy(dst, streamReader)
		done <- true
		if err != nil {
			log.Println(err)
			return
		} 
	}()

	// wait until one of the connections closes
	<- done

	// close both connections
	streamReader.Close() // when this connection handler exits, close the connection
	dst.Close()
}

// passphrase using PBKDF2
func generateKey(pwdfile string) []byte {
	// open pwdfile
	file, err := os.Open(pwdfile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// read from pwdfile
	pwd := make([]byte, 32)
	_, err = file.Read(pwd)
	if err != nil {
		log.Fatal(err)
	}

	// derive aes key from pwdfile
	return pbkdf2.Key([]byte(pwd), []byte(SALT), 4096, 32, sha256.New)
}

func generateCipher(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// create aes cipher
	aesCipher, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	return aesCipher
}

// Data should be encrypted/decrypted using AES-256 in GCM mode in both
// directions. You should derive an appropriate AES key from the supplied
// passphrase using PBKDF2.
func encrypt(byteStream []byte, aesCipher cipher.AEAD) []byte {
	// Number only used once
	nonce := make([]byte, aesCipher.NonceSize())

	// reads exactly NonceSize random bytes into nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// encrypt bytestream
	encrypedStream := aesCipher.Seal(nonce, nonce, byteStream, nil)
	return encrypedStream
}

func decrypt(byteStream []byte, aesCipher cipher.AEAD) []byte {
	// get nonce from byteStream
	ns := aesCipher.NonceSize()
	nonce, encryptedStream := byteStream[:ns], byteStream[ns:]

	decryptedStream, err := aesCipher.Open(nil, nonce, encryptedStream, nil)
	if err != nil {
		log.Println(err)
		return nil
	}

	log.Printf("%s", string(decryptedStream))
	return decryptedStream
 }
