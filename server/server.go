package main
import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
)
func main() {
	cert, err := tls.LoadX509KeyPair("static/server.crt", "static/server.key")
	if err != nil {
		log.Println(err)
		return
	}
	certBytes, err := ioutil.ReadFile("static/rsaCa.crt")
	if err != nil {
		panic("Unable to read cert.pem")
	}
	certBytes2, err := ioutil.ReadFile("static/eccCa.crt")
	if err != nil {
		panic("Unable to read cert.pem")
	}
	certBytes3, err := ioutil.ReadFile("static/CWCA_SM2.cer")
	if err != nil {
		panic("Unable to read cert.pem")
	}
	certBytes4, err := ioutil.ReadFile("static/HXCA_SM2.cer")
	if err != nil {
		panic("Unable to read cert.pem")
	}
	certBytes5, err := ioutil.ReadFile("static/ROOTCA_SM2.cer")
	if err != nil {
		panic("Unable to read cert.pem")
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		panic("failed to parse root certificate")
	}
	ok2 := clientCertPool.AppendCertsFromPEM(certBytes2)
	if !ok2 {
		panic("failed to parse root certificate")
	}
	ok3 := clientCertPool.AppendCertsFromPEM(certBytes3)
	if !ok3 {
		panic("failed to parse root certificate")
	}
	ok4 := clientCertPool.AppendCertsFromPEM(certBytes4)
	if !ok4 {
		panic("failed to parse root certificate")
	}
	ok5 := clientCertPool.AppendCertsFromPEM(certBytes5)
	if !ok5 {
		panic("failed to parse root certificate")
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}
	ln, err := tls.Listen("tcp", ":8200", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConn(conn)
	}
}
func handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}
		println(msg)
		n, err := conn.Write([]byte("world\n"))
		if err != nil {
			log.Println(n, err)
			return
		}
	}
}