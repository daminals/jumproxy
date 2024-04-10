package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"net"
	"time"

	// "fmt"
	"io"
	"log"
	"os"

	pbkdf2 "golang.org/x/crypto/pbkdf2"
)

const (
	SALT = "THIS IS A VERY SECURE SALT. ZEBRA SMARTPHONE BANANA CLOWN"
	CHUNK_SIZE = 1024
)

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
	// loop until EOF or control c
	byteReader := io.Reader(os.Stdin)
	aesKey := generate_key(*pwdfile)

	if *listenport == "" {
		client(byteReader, aesKey, destination, port)
	} else {
		server(aesKey, *listenport, destination, port)
	}
}

func client(byteReader io.Reader, aesKey []byte, destination, port string) { // take in pwdfile, destination, port
	for {
		byteStream := make([]byte, 512)
		_, err := byteReader.Read(byteStream) // don't care about the number of bytes read
		if err == io.EOF { // break on EOF
			break
		}
		if err != nil {
			log.Println(err)
		}
		// create a connection to destination:port
		conn, err := net.Dial("tcp", destination + ":" + port)
		if err != nil {
			log.Fatal(err)
		}

		// encrypt the bytestream
		encryptedStream := encrypt(byteStream, aesKey)
		// send the encrypted bytestream to the server
		send(encryptedStream, conn)
		// response := recv(conn)

		// read response from server
		// decryptedResponse := decrypt(response, aesKey)
		// log.Printf("%s", string(decryptedResponse))
	}
}	

func server(aesKey []byte, listenport, destination, port string) { // take in pwdfile, listenport
	// listen on listenport
	ln, err := net.Listen("tcp", ":" + listenport)
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

		go handleConnection(conn, aesKey, destination, port) // handle connection
	}
}

func handleConnection(conn net.Conn, aesKey []byte, destination, port string) {
		// read from connection 
		encryptedStream := recv(conn)
		byteStream := decrypt(encryptedStream, aesKey)

		// create a two-way stream with destination:port
		dst, err := net.Dial("tcp", destination + ":" + port)
		if err != nil {
			log.Fatal(err)
		}
		defer dst.Close()

		// send decrypted bytes to destination:port
		if byteStream != nil {
			send(byteStream, dst)
		}


	// 	go func() {
	// 		defer conn.Close()

	// 	// read response from destination:port
	// 	response := recv(dst)
	// 	log.Println("Reading response from destination:port: ", string(response))

	// 	// encrypt response and return it to client
	// 	encryptedResponse := encrypt(response, aesKey)
	// 	_, err = conn.Write(encryptedResponse)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// }()

	// return encryptedResponse
}

// func sendProxy(byteStream, aesKey []byte, conn net.Conn) error {
// 		streams := [][]byte{}

// 		// encrypt the bytes and pad out to exactly chunk size
// 		encryptedStream := encrypt(byteStream, aesKey)

// 		// check if encryptedStream is less than chunk size
// 		// if len(encryptedStream) <= CHUNK_SIZE {
// 		// 	encryptedStream = append(encryptedStream, make([]byte, CHUNK_SIZE - len(byteStream))...)
// 		// 	streams = append(streams, encryptedStream)
// 		// } else { // if it is not, break up plaintext into chunks
// 		// 	// check how many chunks we need by dividing the length of the encryptedStream by CHUNK_SIZE
// 		// 	chunks := len(encryptedStream) / CHUNK_SIZE
// 		// 	// split up the bytestream into equal size chunks
// 		// 	for i := 0; i < chunks; i++ {


// 		// 	}


// 			// split the byteStream into chunks

// 			// for i := 0; i < chunks || i*CHUNK_SIZE>len(byteStream); i++ {
// 			// 	bytestreamLen := len(byteStream)
// 			// 	start := i * CHUNK_SIZE
// 			// 	end := start + CHUNK_SIZE
// 			// 	// check if end is greater than bytestreamLen
// 			// 	if end > bytestreamLen {
// 			// 		end = bytestreamLen
// 			// 	}
// 			// 	// encrypt the chunk
// 			// 	encryptedChunk := encrypt(byteStream[start:end], aesKey)
// 			// 	if len(encryptedChunk) < CHUNK_SIZE { // pad out to exactly chunk size
// 			// 		encryptedChunk = append(encryptedChunk, make([]byte, CHUNK_SIZE - len(encryptedChunk))...)
// 			// 	}
// 			// 	streams = append(streams, encryptedChunk)
// 		// 	}
// 		// }

// 		// // send encrypted chunks to remote server
// 		// for _, stream := range streams {
// 		// 	_, err := conn.Write(stream)
// 		// 	if err != nil {
// 		// 		log.Fatal(err)
// 		// 	}
// 		// }	
// 		return nil
// }

// func sendPlainText(byteStream []byte, conn net.Conn) error {
// 	_, err := conn.Write(byteStream)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	return nil
// }

func send(byteStream []byte, conn net.Conn) {
	_, err := conn.Write(byteStream)
	if err != nil {
		log.Fatal(err)
	}
}

func recvProxy(conn net.Conn, aesKey []byte) []byte {
	// expect to receive a chunk of exactly CHUNK_SIZE
	response := make([]byte, CHUNK_SIZE)
	_, err := conn.Read(response)
	if err != nil {
		log.Fatal(err)
	}
	// decrypt the response
	decryptedResponse := decrypt(response, aesKey)
	return decryptedResponse
}

func recv(conn net.Conn) []byte {
	response := []byte{}
	chunk := make([]byte, 1024)
	done := make(chan bool)
	// 2 second deadline - no hanging
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))

	go func() {
		for {
			n, err := conn.Read(chunk)
			if err == io.EOF || n == 0 {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			response = append(response, chunk[:n]...)
		}
		done <- true
	}()

	<-done
	return response
}



func generate_key(pwdfile string) ([]byte) {
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


// Data should be encrypted/decrypted using AES-256 in GCM mode in both
// directions. You should derive an appropriate AES key from the supplied
// passphrase using PBKDF2.
func encrypt(byteStream, key []byte) ([]byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// create aes cipher
	aesCipher, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Number only used once
	nonce := make([]byte, aesCipher.NonceSize())

	// reads exactly NonceSize random bytes into nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// encrypt bytestream
	encrypedStream := aesCipher.Seal(nonce, nonce, byteStream, nil)
	// log.Printf("%x\n", encrypedStream)

	return encrypedStream
}

func decrypt(byteStream, key []byte) ([]byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesCipher, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

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