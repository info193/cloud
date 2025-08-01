package main

import (
	"cloud/config"
	"cloud/ssl"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	data, err := os.ReadFile("../config.yaml")
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// 解析YAML内容到Config结构体中
	var conf config.Config
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		fmt.Println(fmt.Sprintf("error: %v", err))
		log.Fatalf("error: %v", err)
	}
	//sslDomains(conf)
	advendSslDomains(conf)
	//upload(conf)
	//createCertificateForPackage(conf, "www.xxxx.com")
	//certLists(conf)
	//listCert(conf)
	//getUserCertificateDetail(conf)
	//CreateCertificateForPackage(conf)
	return
}

// ssl证书域名
func sslDomains(conf config.Config) {
	sslClient := ssl.CreateNewSSL(&conf)

	// 查询用户证书或者订单列表
	resp, err := sslClient.ListUserCertificate(1, 500, "CERT", "")
	if err != nil {
		fmt.Println("获取用户ssl证书失败")
		return
	}
	// 过期日期
	advendDate := time.Now().Add(time.Duration(100) * 24 * time.Hour).Format("2006-01-02")
	if resp.TotalCount >= 1 {
		for _, value := range resp.CertificateOrderList {
			if advendDate >= value.EndDate {
				certName := fmt.Sprintf("%v_%v", value.CommonName, value.EndDate)
				fmt.Println(fmt.Sprintf("Domain:%v，CertificateId:%v，EndDate:%v，certName:%v", value.CommonName, value.CertificateId, value.EndDate, certName))
			}
		}
	}
}
func advendSslDomains(conf config.Config) {
	// 删除本地证书
	ssl.ClearLocalSsl()
	sslClient := ssl.CreateNewSSL(&conf)
	// 查询用户证书或者订单列表
	resp, err := sslClient.ListUserCertificate(1, 500, "CERT", "")
	if err != nil {
		fmt.Println("获取用户ssl证书失败")
		return
	}

	// 10天到期证书
	advendDate := time.Now().Add(time.Duration(10) * 24 * time.Hour).Format("2006-01-02")
	advendDomain := make(map[string]string)
	if resp.TotalCount >= 1 {
		for _, value := range resp.CertificateOrderList {
			if advendDate >= value.EndDate {
				// 排重
				if v, ok := advendDomain[value.CommonName]; ok {
					if v <= value.EndDate {
						advendDomain[value.CommonName] = value.EndDate
					}
				} else {
					advendDomain[value.CommonName] = value.EndDate
				}
			}
		}
	}
	applyCertDomain := make(map[string]int64, 0)
	if len(advendDomain) >= 1 {
		for key, _ := range advendDomain {
			params := make(map[string]string, 0)
			params["phone"] = conf.Ssl.Package.Phone
			params["email"] = conf.Ssl.Package.Email
			params["domain"] = key
			params["username"] = conf.Ssl.Package.Username
			// 查询用户证书或者订单列表
			orderId, result, err := sslClient.CreateCertificateForPackage(params)
			if err != nil {
				fmt.Println("创建用户ssl证书失败", err)
				return
			}
			if !result {
				fmt.Println("创建用户ssl证书失败")
				return
			}
			applyCertDomain[key] = orderId
		}
	}
	applyCertLen := len(applyCertDomain)
	for {
		if applyCertLen <= 0 {
			break
		}
		// 延迟
		for temDomain, orderId := range applyCertDomain {
			resp, err := sslClient.DescribeCertificateState(orderId)
			if err != nil {
				fmt.Println("查询申请证书信息失败", err)
				return
			}
			// 已签发
			if resp.Type == "certificate" {
				sslClient.Download(temDomain, resp.Certificate, "pem")
				sslClient.Download(temDomain, resp.PrivateKey, "key")
				delete(applyCertDomain, temDomain)
				applyCertLen--
			}
			// 审核中
			if resp.Type == "process" {
				fmt.Println(fmt.Sprintf("domain:%v Under review", temDomain))
				continue
			}
			// 待申请
			if resp.Type == "payed" {
				fmt.Println(fmt.Sprintf("domain:%v Under payed", temDomain))
				continue
			}
			// 审核失败
			if resp.Type == "verify_fail" {
				fmt.Println(fmt.Sprintf("domain:%v Audit failed", temDomain))
				continue
			}
			// 状态未知
			if resp.Type == "unknow" {
				fmt.Println(fmt.Sprintf("domain:%v ssl unknow", temDomain))
				continue
			}
		}
		fmt.Println("等待3分钟后再次检测", time.Now().Format(time.DateTime))
		if applyCertLen <= 0 {
			break
		}
		time.Sleep(time.Minute * 3)
	}

	fmt.Println("上传证书")
	upload(conf)
}

func createCertificateForPackage(conf config.Config, domain string) {
	sslClient := ssl.CreateNewSSL(&conf)
	params := make(map[string]string, 0)
	params["phone"] = conf.Ssl.Package.Phone
	params["email"] = conf.Ssl.Package.Email
	params["domain"] = domain
	params["username"] = conf.Ssl.Package.Username
	// 查询用户证书或者订单列表
	orderId, result, err := sslClient.CreateCertificateForPackage(params)
	if err != nil {
		fmt.Println("创建用户ssl证书失败", err)
		return
	}
	if !result {
		fmt.Println("创建用户ssl证书失败")
		return
	}
	fmt.Println(orderId, "------------------")
}
func certLists(conf config.Config) {
	sslClient := ssl.CreateNewSSL(&conf)

	// 查询用户证书或者订单列表
	resp, err := sslClient.CertLists(1, 500, "aliyunPCA")
	if err != nil {
		fmt.Println("获取用户ssl证书失败")
		return
	}
	fmt.Println(fmt.Sprintf("%+v", resp))
}
func listCert(conf config.Config) {
	sslClient := ssl.CreateNewSSL(&conf)
	// 查询用户证书或者订单列表
	resp, err := sslClient.ListCert(1, 500)
	if err != nil {
		fmt.Println("获取用户ssl证书失败")
		return
	}
	fmt.Println(fmt.Sprintf("%+v", resp))
}
func getUserCertificateDetail(conf config.Config) {
	sslClient := ssl.CreateNewSSL(&conf)
	// 查询用户证书或者订单列表
	resp, err := sslClient.CertDetail(19505443)
	if err != nil {
		fmt.Println("获取用户ssl证书失败")
		return
	}
	fmt.Println("domain:", resp.Common)
	fmt.Println("name:", resp.Name)
	fmt.Println("Cert:", resp.Cert)
	fmt.Println("key:", resp.Key)
	fmt.Println("=========================================")
	fmt.Println("Id:", resp.Id)
	fmt.Println("CertIdentifier:", fmt.Sprintf("%v-%v", resp.Id, conf.Ssl.RegionId))
	fmt.Println("StartDate:", resp.StartDate)
	fmt.Println("EndDate:", resp.EndDate)
	fmt.Println("Expired:", resp.Expired)
	fmt.Println("-***************************************************************************")
}

func upload(conf config.Config) {
	conf.Ssl.AccessKeyId = conf.UploadSsl.AccessKeyId
	conf.Ssl.AccessKeySecret = conf.UploadSsl.AccessKeySecret
	conf.Ssl.RegionId = conf.UploadSsl.RegionId
	sslClient := ssl.CreateNewSSL(&conf)

	dirPath := filepath.Join("../cert")
	fileInfo, err := os.Stat(dirPath)
	if fileInfo.IsDir() && err == nil {
		var files []string
		var walkFunc = func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				files = append(files, path)
			}
			return nil
		}
		err := filepath.Walk(dirPath, walkFunc)
		if err != nil {
			fmt.Println("目录读取失败", err)
			return
		}
		cerfLists := make(map[string]map[string]string, 0)
		if len(files) >= 1 {
			for _, value := range files {
				baseName := filepath.Base(value)
				domainName := strings.TrimSuffix(baseName, filepath.Ext(baseName))
				if _, ok := cerfLists[domainName]; !ok {
					cerfLists[domainName] = make(map[string]string, 0)
				}

				if filepath.Ext(baseName) == ".pem" {
					cerfLists[domainName]["pem"] = value
				}
				if filepath.Ext(baseName) == ".key" {
					cerfLists[domainName]["key"] = value
				}
			}
		}
		// 初始化上传下载的ssl证书
		if len(cerfLists) >= 1 {
			for _, value := range cerfLists {
				id, name, tempDomain, err := sslClient.Upload(value["pem"], value["key"])
				if err != nil {
					fmt.Println("证书上传失败")
					return
				}
				// 上传成功，证书名称： www.xxxx.com_2025-07-27 证书ID： 19604598 domain www.xxxx.com
				fmt.Println("上传成功，证书名称：", name, "证书ID：", id, "domain", tempDomain)
			}
		}
	}
}
