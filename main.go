package main

import (
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"pappca/cert"
)

type PAPP struct {
	PAPPName            string  `yaml:"PAPPName"`
	Country             string  `yaml:"Country"`
	Organization        string  `yaml:"Organization"`
	OrganizationalUnit  string  `yaml:"OrganizationalUnit"`
	Province            string  `yaml:"Province"`
	Locality            string  `yaml:"Locality"`
	StreetAddress       string  `yaml:"StreetAddress"`
}

//Config   系统配置
type Config struct{
	PappNumber          int      `yaml:"PAPPNumber"`
	PAPPs               []PAPP   `yaml:"PAPPs"`
}

func main() {

	// pappca -cmd init          生成超级链根证书和私钥
	// pappca -cmd generate      生成yaml文件中所有PAPP的证书和私钥

	cmd := flag.String("cmd", "", "init generate start")
	flag.Parse()

	switch *cmd{
	case "init":
		Init()
	case "generate":
		Generate()

	default:
		fmt.Println("No this cmd. please input the right cmd")
		fmt.Println("pappca -cmd init          生成超级链根证书和私钥")
		fmt.Println("pappca -cmd generate      生成yaml文件中所有PAPP的证书和私钥")
	}
}

func Init(){

	// 生成超级链根证书和私钥
	certInfo := cert.CertInformation{
		Country:            []string{"China"},
		Organization:       []string{"buaa"},
		OrganizationalUnit: []string{"www.buaa.edu.cn"},
		EmailAddress:       []string{"wlkjaq@buaa.edu.cn"},
		StreetAddress:      []string{"37"},
		Province:           []string{"Beijing"},
		Locality:           []string{"haidian"},
		SubjectKeyId:       []byte{6, 5, 4, 3, 2, 1},
	}
	rootCertFilePath := "./crypto/superchain/ca.crt"
	rootPrivateKeyFilePath := "./crypto/superchain/ca.key"

	// 清空原有的文件
	_ = os.RemoveAll("./crypto/superchain")

	err := cert.CreateRootCertAndRootPrivateKey(certInfo,rootCertFilePath,rootPrivateKeyFilePath)
	if err != nil{
		fmt.Println("Create Root Cert And Root Private Key Error: ",err)
		panic("Failed To Create Root Cert And Root Private Key.")
	}

	fmt.Println("=============== Create RootCert And RootPrivateKey Successful ===============")
}

func Generate(){

	// 确认是否已经生成根证书和根私钥
	rootCertFilePath := "./crypto/superchain/ca.crt"
	rootPrivateKeyFilePath := "./crypto/superchain/ca.key"

	if cert.PathIsExist(rootCertFilePath) == false {
		panic("No Superchain RootCert!")
	}
	if cert.PathIsExist(rootPrivateKeyFilePath) == false {
		panic("No Superchain Private Key!")
	}

	// 获取配置文件数据
	var setting Config
	config, err := ioutil.ReadFile("./papp.yaml")
	if err != nil {
		panic("read papp.yaml failed.")
	}
	err1 := yaml.Unmarshal(config,&setting)
	if err1 != nil{
		panic("Get config from papp.yaml failed.")
	}

	//number := setting.PappNumber
	myPAPPs:= setting.PAPPs

	//// 清空原有的文件
	//_ = os.RemoveAll("./crypto/PAPPs")

	// 为每个PAPP生成私钥、证书、根证书
	for i:= 0; i< len(myPAPPs); i++{
		tempInfo:= cert.CertInformation{
			Country:             []string{myPAPPs[i].Country},
			Organization:        []string{myPAPPs[i].Organization},
			OrganizationalUnit:  []string{myPAPPs[i].OrganizationalUnit},
			StreetAddress:       []string{myPAPPs[i].StreetAddress},
			Province:            []string{myPAPPs[i].Province},
			Locality:            []string{myPAPPs[i].Locality},
		}
		// 生成证书
		err := cert.CreateCertWithInfo(tempInfo,setting.PAPPs[i].PAPPName, rootCertFilePath, rootPrivateKeyFilePath)
		if err != nil {
			panic("Failed To Create Cert With Info.")
		}
	}

	fmt.Println("=============== Create PAPPs Cert With Info Successful ===============")
}