package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"net"
	// "time"

	// "fmt"
	"io"
	"log"
	"os"

	pbkdf2 "golang.org/x/crypto/pbkdf2"
)

const (
	SALT       = "THIS IS A VERY SECURE SALT. ZEBRA SMARTPHONE BANANA CLOWN"
	CHUNK_SIZE = 1024
)

type StreamReadWriter struct {
	Source io.ReadWriter
	Cipher cipher.AEAD
} 

// Write implements io.Writer.
func (self StreamReadWriter) Write(byteStream []byte) (n int, err error) {
	log.Println("writing")

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

func (self StreamReadWriter) Read(byteStream []byte) (n int, err error) {
	log.Println("reading")

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

	// read stdin
	aesCipher := generateCipher(generateKey(*pwdfile))

	if *listenport == "" {
		client(aesCipher, destination, port)
	} else {
		server(aesCipher, *listenport, destination, port)
	}
}

func client(aesCipher cipher.AEAD, destination, port string) { // take in pwdfile, destination, port
	for { // loop until EOF or control c
		// create a connection to destination:port
		conn, err := net.Dial("tcp", destination+":"+port)
		if err != nil {
			log.Fatal(err)
		}

		// open a stream writer with the server connection
		streamWriter := StreamReadWriter{
			Source: conn,
			Cipher: aesCipher,
		}

		// send the encrypted bytestream to the server
		_, err = io.Copy(streamWriter, os.Stdin)
		if err != nil {
			log.Fatal(err)
		}

		// read response from server
		_, err = io.Copy(os.Stderr, streamWriter)
		if err != nil {
			log.Fatal(err)
		}
	}
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
		streamReader := StreamReadWriter{
			Source: conn,
			Cipher: aesCipher,
		}

		go handleConnection(streamReader, destination, port) // handle connection
	}
}

func handleConnection(streamReader StreamReadWriter, destination, port string) {
	// create a two-way stream with destination:port
	dst, err := net.Dial("tcp", destination+":"+port)
	if err != nil {
		log.Fatal(err)
	}

	// send decrypted bytes to destination:port
	_, err = io.Copy(dst, streamReader) 
	if err != nil {
		log.Fatal(err)
	}

	// send the response back to the client
	if _, err = io.Copy(streamReader, dst); err != nil {
		log.Fatal(err)
	}
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
