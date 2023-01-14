package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

var certfile = flag.String("cert", "", "Certficate file path")
var privatefile = flag.String("private", "", "Private key file path")

func keyByteToString(publicKeyDer []byte) (publicKeyPem string) {
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem = string(pem.EncodeToMemory(&publicKeyBlock))
	return

}

func getPublicKey(certBlock []byte, keyBlock []byte) (publicKeyFromCert string, publicKeyFromPrivate string, err error) {
	certBody, err := x509.ParseCertificate(certBlock)
	fmt.Println("DomainNames: ", certBody.DNSNames)
	fmt.Println("Begin: ", certBody.NotBefore)
	fmt.Println("  End: ", certBody.NotAfter)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	//可以根据证书结构解析
	// fmt.Println(certBody.SignatureAlgorithm)
	// fmt.Println(certBody.PublicKeyAlgorithm)
	keyBody, err := x509.ParsePKCS1PrivateKey(keyBlock)
	if err != nil {
		fmt.Println(err)
		return "", "", err
	}
	// 提取公钥
	publicKeyDerFromCert, _ := x509.MarshalPKIXPublicKey(certBody.PublicKey)
	publicKeyDerFromKey, _ := x509.MarshalPKIXPublicKey(&keyBody.PublicKey)
	publicKeyFromCert = keyByteToString(publicKeyDerFromCert)
	publicKeyFromPrivate = keyByteToString(publicKeyDerFromKey)
	return publicKeyFromCert, publicKeyFromPrivate, nil

}

func readFromFile(filepath string) (certBlock *pem.Block, err error) {
	//读取证书并解码
	pemTmp, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Println(err)
		return
	}
	// certBlock, restBlock := pem.Decode(pemTmp)
	certBlock, _ = pem.Decode(pemTmp)
	if certBlock == nil {
		fmt.Println(err)
		return
	}
	//可从剩余判断是否有证书链等，继续解析
	// fmt.Println(restBlock)
	return

}

func checkArgs() {
	chktag := false
	if *certfile == "" {
		fmt.Println("No Certificate file")
		chktag = true
	}
	if *privatefile == "" {
		fmt.Println("No Private key file")
		chktag = true
	}
	if chktag == true {
		os.Exit(1)
	}
}

func main() {
	flag.Parse()
	checkArgs()
	//读取证书并解码
	certBlock, err := readFromFile(*certfile)
	if err != nil {
		fmt.Println(err)
		return
	}
	keyBlock, err := readFromFile(*privatefile)
	if err != nil {
		fmt.Println(err)
		return
	}
	pubKeyStrFromCert, pubKeyStrFromKey, err := getPublicKey(certBlock.Bytes, keyBlock.Bytes)
	if pubKeyStrFromCert == pubKeyStrFromKey {
		fmt.Println("Certficate matches Private Key")
	} else {
		fmt.Println("Certficate and Private Key does not match !")
	}
	// fmt.Println("Cert Pub Key:")
	// fmt.Println(pubKeyStrFromCert)
	// fmt.Println("Key Pub Key:")
	// fmt.Println(pubKeyStrFromKey)

}
