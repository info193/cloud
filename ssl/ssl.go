package ssl

import (
	"cloud/config"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cas"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Ssl struct {
	config *config.Config
	client *cas.Client
}

func CreateNewSSL(conf *config.Config) *Ssl {
	// 1. 初始化客户端
	newConfig := sdk.NewConfig()
	// 账号凭证
	credential := credentials.NewAccessKeyCredential(conf.Ssl.AccessKeyId, conf.Ssl.AccessKeySecret)
	casClient, err := cas.NewClientWithOptions(conf.Ssl.RegionId, newConfig, credential)
	if err != nil {
		fmt.Println("创建CAS客户端失败:", err)
		return nil
	}
	return &Ssl{config: conf, client: casClient}
}

// 证书校验
func VerifyCert(domain string) *config.VerifyCertDomain {
	url := fmt.Sprintf("https://%v", domain)
	// 使用http.Get获取HTTPS连接
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(fmt.Sprintf("domain:%v， VerifyCert err:%v", domain, err))
		return nil
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		fmt.Println(fmt.Sprintf("domain:%v ，No TLS connection established", domain))
		return nil
	}
	// 从响应中提取TLS连接状态
	cert := resp.TLS.PeerCertificates[0] // 获取第一个证书（通常是服务器证书）
	subject := strings.Split(fmt.Sprintf("%v", cert.Subject), "=")
	return &config.VerifyCertDomain{Domain: subject[1], StartDate: cert.NotBefore.Format("2006-01-02"), EndDate: cert.NotAfter.Format("2006-01-02")}
}
func ClearLocalSsl() {
	dirPath := filepath.Join("../cert")
	fileInfo, err := os.Stat(dirPath)
	if fileInfo.IsDir() && err == nil {
		var files []string
		//方法一
		var walkFunc = func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				files = append(files, path)
			}
			return nil
		}
		err := filepath.Walk(dirPath, walkFunc)
		if err != nil {
			fmt.Println("目录读取失败", err)
			return
		}
		if len(files) >= 1 {
			for _, value := range files {
				os.RemoveAll(value)
			}
			os.Mkdir("../cert", 0755)
		}

	}
}

func (l *Ssl) Download(domain string, content string, suffix string) bool {
	dirPath := filepath.Join("../cert", domain)
	_, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(dirPath, 0755)
			if err != nil {
				fmt.Println("Error creating file:", err)
				return false
			}
		}
	}

	filenamePath := filepath.Join("../cert", domain, fmt.Sprintf("%v.%v", domain, suffix))
	file, err := os.Create(filenamePath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return false
	}
	defer file.Close()                                      // 确保文件最终会被关闭
	err = os.WriteFile(filenamePath, []byte(content), 0644) // 使用 []byte 作为参数写入内容 直接写入文件内容（覆盖模式）
	if err != nil {
		fmt.Println("Error writing to file with WriteFile:", err)
		return false
	}
	return true
}

// 解析证书
func ParseCertExpiryDate(certFile string) (*x509.Certificate, error) {
	// 读取证书文件
	certData, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
		return nil, err
	}

	// 解析 PEM 编码的证书
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode PEM block containing certificate")
		return nil, errors.New("Failed to decode PEM block containing certificate")
	}

	// 解析证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
		return nil, err

	}
	return cert, nil
}

func (l *Ssl) Upload(certFile, keyFile string) (int64, string, string, error) {

	// 1.获取证书域名
	baseName := filepath.Base(certFile)
	domain := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	// 2.解析证书获取证书有效期
	cert, err := ParseCertExpiryDate(certFile)
	if err != nil {
		return 0, "", "", err
	}

	// 3.设置证书名称
	certName := fmt.Sprintf("%v_%v", domain, cert.NotAfter.Format("2006-01-02"))

	// 4.读取证书
	certContent, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Println("读取证书文件失败:", err)
		return 0, "", "", err
	}

	// 5.读取私钥文件
	keyContent, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Println("读取私钥文件失败:", err)
		return 0, "", "", err
	}

	// 6. 初始化设置上传证书参数
	uploadRequest := cas.CreateUploadUserCertificateRequest()
	uploadRequest.Scheme = "https"
	uploadRequest.Name = certName
	uploadRequest.Cert = string(certContent)
	uploadRequest.Key = string(keyContent)

	// 7.上传证书
	uploadResponse, err := l.client.UploadUserCertificate(uploadRequest)
	if err != nil {
		fmt.Println("上传证书失败:", err)
		return 0, "", "", err
	}

	return uploadResponse.CertId, certName, domain, nil
}
func (l *Ssl) CertDetail(certid int64) (*cas.GetUserCertificateDetailResponse, error) {
	getUserCertificateDetailRequest := cas.CreateGetUserCertificateDetailRequest()
	getUserCertificateDetailRequest.CertId = requests.NewInteger64(certid)
	getUserCertificateDetailRequest.CertFilter = requests.NewBoolean(false)
	response, err := l.client.GetUserCertificateDetail(getUserCertificateDetailRequest)
	if err != nil {
		fmt.Println("获取证书详情失败")
		return nil, err
	}

	return response, nil
}

// 申请创建ssl证书
func (l *Ssl) CreateCertificateForPackage(param map[string]string) (int64, bool, error) {
	createCertificateForPackageRequestRequest := cas.CreateCreateCertificateForPackageRequestRequest()
	createCertificateForPackageRequestRequest.ProductCode = "digicert-free-1-free"
	createCertificateForPackageRequestRequest.Phone = param["phone"]
	createCertificateForPackageRequestRequest.Email = param["email"]
	createCertificateForPackageRequestRequest.Domain = param["domain"]
	createCertificateForPackageRequestRequest.Username = param["username"]
	createCertificateForPackageRequestRequest.ValidateType = "DNS"
	response, err := l.client.CreateCertificateForPackageRequest(createCertificateForPackageRequestRequest)
	if err != nil {
		fmt.Println("创建证书失败", err)
		return 0, false, err
	}
	return response.OrderId, response.IsSuccess(), nil
}

// 查询证书申请订单状态
func (l *Ssl) DescribeCertificateState(orderId int64) (*cas.DescribeCertificateStateResponse, error) {
	describeCertificateStateRequest := cas.CreateDescribeCertificateStateRequest()
	describeCertificateStateRequest.OrderId = requests.NewInteger64(orderId)
	response, err := l.client.DescribeCertificateState(describeCertificateStateRequest)
	if err != nil {
		fmt.Println("获取证书详情失败", err)
		return nil, err
	}
	return response, nil
}

// 查询用户证书或者订单列表
func (l *Ssl) ListUserCertificate(page, limit int64, orderType string, status string) (*cas.ListUserCertificateOrderResponse, error) {
	listUserCertificateOrderRequest := cas.CreateListUserCertificateOrderRequest()
	listUserCertificateOrderRequest.CurrentPage = requests.NewInteger64(page)
	listUserCertificateOrderRequest.ShowSize = requests.NewInteger64(limit)
	listUserCertificateOrderRequest.OrderType = orderType // BUY:售卖订单，UPLOAD:上传证书，CERT：同时返回签发证书和上传证书
	if status != "" {
		listUserCertificateOrderRequest.Status = status
		/*
			status 值
			PAYED：待申请，当 OrderType=CPACK 或者 BUY 有效。
			CHECKING：审核中，当 OrderType=CPACK 或者 BUY 有效。
			CHECKED_FAIL：审核失败，当 OrderType=CPACK 或者 BUY 有效。
			ISSUED：已签发。
			WILLEXPIRED：即将过期。
			EXPIRED：已过期。
			NOTACTIVATED：未激活，当 OrderType=CPACK 或者 BUY 有效。
			REVOKED：吊销完成，当 OrderType=CPACK 或者 BUY 有效。
		*/
	}

	response, err := l.client.ListUserCertificateOrder(listUserCertificateOrderRequest)
	if err != nil {
		fmt.Println("获取证书详情失败")
		return nil, err
	}
	return response, nil
}

func (l *Ssl) CertLists(page, limit int64, isType string) (*cas.ListCertWarehouseResponse, error) {
	listCertWarehouseRequest := cas.CreateListCertWarehouseRequest()
	listCertWarehouseRequest.CurrentPage = requests.NewInteger64(page)
	listCertWarehouseRequest.ShowSize = requests.NewInteger64(limit)
	listCertWarehouseRequest.Type = isType // **uploadCA **：上传的 CA 证书，即包含完整证书链的 CA 证书。  **uploadPCA **：上传的证书，包括自签证书、第三方签发的证书或阿里云签发的证书等。 **aliyunPCA **：阿里云 PCA 证书。
	response, err := l.client.ListCertWarehouse(listCertWarehouseRequest)
	if err != nil {
		fmt.Println("获取证书详情失败", err)
		return nil, err
	}
	return response, nil
}

func (l *Ssl) ListCert(page, limit int64) (*cas.ListCertResponse, error) {
	listCertRequest := cas.CreateListCertRequest()
	listCertRequest.CurrentPage = requests.NewInteger64(page)
	listCertRequest.ShowSize = requests.NewInteger64(limit)
	response, err := l.client.ListCert(listCertRequest)
	if err != nil {
		fmt.Println("获取证书详情失败", err)
		return nil, err
	}
	return response, nil
}
