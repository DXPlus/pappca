package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

type CertInformation struct {
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	EmailAddress       []string
	Province           []string
	StreetAddress      []string
	SubjectKeyId       []byte
	Locality           []string
}

// 创建根证书和根私钥
func CreateRootCertAndRootPrivateKey(info CertInformation, rootCertFilePath, rootPrivateKeyFilePath string) error {

	dirPath := "./crypto/superchain"
	err0 := os.MkdirAll(dirPath, os.ModePerm)
	if err0 != nil {
		return err0
	}

	// use certInformation to new cert
	certTemp := newCertificate(info)
	// generate private key and public key
	rootPrivateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	// create root cert []byte
	rootCertificateByte, _ := x509.CreateCertificate(rand.Reader, certTemp, certTemp, &rootPrivateKey.PublicKey, rootPrivateKey)
	// get private key []bytes
	rootPrivateKeyByte, _ := x509.MarshalECPrivateKey(rootPrivateKey)

	//fmt.Println("rootCertificateByte:",rootCertificateByte)

	// write root certificate
	err := write(rootCertFilePath, "CERTIFICATE", rootCertificateByte)
	if err != nil {
		return err
	}
	// write root private key
	err1 := write(rootPrivateKeyFilePath, "PRIVATE KEY", rootPrivateKeyByte)
	if err1 != nil {
		return err1
	}

	return nil
}

// crypto/PAPPs/PAPP1/client.crt
// crypto/PAPPs/PAPP1/client.key
// crypto/PAPPs/PAPP1/ca.crt
func CreateCertWithInfo(info CertInformation, PAPPName, rootCertFilePath, rootPrivateKeyFilePath string) error {

	certFilePath := "./crypto/PAPPs/" + PAPPName + "/client.crt"
	privateKeyFilePath := "./crypto/PAPPs/" + PAPPName + "/client.key"
	caFilePath := "./crypto/PAPPs/" + PAPPName + "/ca.crt"
    dirPath := "./crypto/PAPPs/" + PAPPName
	err0 := os.MkdirAll(dirPath, os.ModePerm)
	if err0 != nil {
		return err0
	}

	// 生成公私钥对
	privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	//publicKey := privateKey.PublicKey
	// 保存私钥到本地
	privB, _ := x509.MarshalECPrivateKey(privateKey)
	err := write(privateKeyFilePath, "PRIVATE KEY", privB)
	if err != nil {
		return err
	}

	// 生成csr
	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            info.Country,
			Organization:       info.Organization,
			OrganizationalUnit: info.OrganizationalUnit,
			Locality:           info.Locality,
			Province:           info.Province,
			StreetAddress:      info.StreetAddress,
			//SubjectKeyId:       info.SubjectKeyId,
		},
		PublicKey: privateKey.PublicKey,
	}
	csrByte, _ := x509.CreateCertificateRequest(rand.Reader, req, privateKey)
	csr, _ := x509.ParseCertificateRequest(csrByte)

	// 使用csr生成临时证书
	tempCert := newCertificateWithCSR(csr)

	// 获取根证书
	certPEM, _ := ioutil.ReadFile(rootCertFilePath)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		panic("Failed to parse root Certificate PEM")
	}
	rootCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("Failed to parse root Certificate PEM: " + err.Error())
	}

	// 获取根私钥
	privR, _ := ioutil.ReadFile(rootPrivateKeyFilePath)
	block2, _ := pem.Decode(privR)
	if block2 == nil {
		panic("Failed to parse root private key")
	}
	rootPrivateKey, err := x509.ParseECPrivateKey(block2.Bytes)
	if err != nil {
		panic(err)
	}

    // 签发证书
	newCert, err := x509.CreateCertificate(rand.Reader, tempCert, rootCertificate, csr.PublicKey, rootPrivateKey)
	if err!=nil {
		fmt.Println("err:",err)
	}

	// 保存证书到本地
	err = write(certFilePath, "CERTIFICATE", newCert)
	if err != nil {
		return err
	}
	// 保存根证书到本地
	err = write(caFilePath, "CERTIFICATE", block.Bytes)
	if err != nil {
		return err
	}

	return nil
}

func newCertificate(info CertInformation) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Country:            info.Country,
			Organization:       info.Organization,
			OrganizationalUnit: info.OrganizationalUnit,
			Province:           info.Province,
			StreetAddress:      info.StreetAddress,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		//SubjectKeyId:          info.SubjectKeyId,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		//EmailAddresses: info.EmailAddress,
	}
}

func newCertificateWithCSR(req *x509.CertificateRequest) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject:      req.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		//SubjectKeyId:          info.SubjectKeyId,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		//EmailAddresses: info.EmailAddress,
	}
}

func PathIsExist(path string) bool {
	_, err := os.Stat(path)
	var exist = false
	if err == nil {
		exist = true
	}
	if os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func write(filename, Type string, p []byte) error {
	File, err := os.Create(filename)
	defer File.Close()
	if err != nil {
		return err
	}
	var b = &pem.Block{Bytes: p, Type: Type}
	err = pem.Encode(File, b)
	if err != nil {
		return err
	}
	return nil
}