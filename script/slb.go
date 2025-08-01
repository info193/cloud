package main

import (
	"cloud/config"
	"cloud/slb"
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
	expireReplace(conf)
	//slbDomain(conf)
	//slbReplaceSSL(conf)
	//deleteSSL(conf)
	return
}
func slbDomain(conf config.Config) {
	if len(conf.Slb.Slbs) < 1 {
		fmt.Println("需配置负载均衡实例ID")
		return
	}
	// 创建slb链接
	slb := slb.CreateNewSlb(&conf)
	for _, slbId := range conf.Slb.Slbs {
		fmt.Println(fmt.Sprintf("**************************************************************** %v start**********************************************************", slbId))
		slb.SetSlb(slbId, 0, "", "")
		_, err := slb.Listeners()
		if err != nil {
			fmt.Println("查询负载均衡监听列表失败", err)
			return
		}

		// 协议扩展域名
		slbDomain, err := slb.ProtocolDomain()
		if err != nil {
			fmt.Println("查询协议扩展域名失败", err)
			return
		}
		for _, value := range slbDomain {
			verifyCert := ssl.VerifyCert(value.Domain)
			if verifyCert != nil {
				fmt.Println(fmt.Sprintf("------------------------ %v start------------------------------", value.Domain))
				fmt.Println(fmt.Sprintf("domain:%v", value.Domain))
				fmt.Println(fmt.Sprintf("certId:%v", value.OldCertId))
				fmt.Println(fmt.Sprintf("serverCertificateId:%v", value.OldServerCertificateId))
				fmt.Println(fmt.Sprintf("certName:%v", value.OldCertName))
				fmt.Println(fmt.Sprintf("startDate:%v", value.OldStartDate))
				fmt.Println(fmt.Sprintf("endDate:%v", value.OldEndDate))
				fmt.Println(fmt.Sprintf("InUseSSLStartDate:%v", verifyCert.StartDate))
				fmt.Println(fmt.Sprintf("InUseSSLEndDate:%v", verifyCert.EndDate))
				fmt.Println(fmt.Sprintf("------------------------ %v end------------------------------", value.Domain))
				fmt.Println()
			}
		}
		fmt.Println(fmt.Sprintf("**************************************************************** %v end**********************************************************", slbId))
	}
}

func expireReplace(conf config.Config) {
	// 获取证书
	dirPath := filepath.Join("../cert")
	fileInfo, err := os.Stat(dirPath)
	if err != nil {
		fmt.Println(fmt.Sprintf("directory does not exist，error：%v", err))
		return
	}
	cerfLists := make(map[string]map[string]string, 0)
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
			fmt.Println(fmt.Sprintf("directory read error : %v", err))
			return
		}
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
	}

	// 创建slb链接
	slb := slb.CreateNewSlb(&conf)
	for _, slbId := range conf.Slb.Slbs {
		slb.SetSlb(slbId, 0, "", "")
		_, err = slb.Listeners()
		if err != nil {
			fmt.Println("查询负载均衡监听列表失败", err)
			return
		}

		// 协议扩展域名
		slbDomain, err := slb.ProtocolDomain()
		if err != nil {
			fmt.Println("查询协议扩展域名失败", err)
			return
		}
		domainList := make(map[string]config.SlbDomain, 0)
		for _, value := range slbDomain {
			if _, oks := cerfLists[value.Domain]; oks {
				domainList[value.Domain] = value
			}
		}

		// 查询用户证书或者订单列表
		sslClient := ssl.CreateNewSSL(&conf)
		resp, err := sslClient.ListUserCertificate(1, 500, "CERT", "")
		if resp.TotalCount >= 1 {
			replaceDomainSSL := make(map[string]string, 0)
			for _, value := range resp.CertificateOrderList {
				if pdVal, ok := domainList[value.CommonName]; ok {
					if val, check := replaceDomainSSL[value.CommonName]; check {
						if val >= value.EndDate {
							continue
						}
					}

					replaceDomainSSL[value.CommonName] = value.EndDate
					certName := fmt.Sprintf("%v_%v", value.CommonName, value.EndDate)
					slb.SetSlb(slbId, value.CertificateId, certName, value.CommonName)
					pdVal.CertId = value.CertificateId
					pdVal.CertName = certName
					// 替换证书
					err = slb.ReplaceSSL(&pdVal)
					if err != nil {
						fmt.Println()
						fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
						continue
					}
				}
			}
		}
	}

	return
}

func slbReplaceSSL(conf config.Config) {
	// 创建slb链接
	slb := slb.CreateNewSlb(&conf)
	for _, slbId := range conf.Slb.Slbs {
		slb.SetSlb(slbId, 0, "", "")
		_, err := slb.Listeners()
		if err != nil {
			fmt.Println("查询负载均衡监听列表失败", err)
			return
		}
		// 协议扩展域名
		slbDomain, err := slb.ProtocolDomain()
		if err != nil {
			fmt.Println("查询协议扩展域名失败", err)
			return
		}
		domainList := make(map[string]config.SlbDomain, 0)
		for _, value := range slbDomain {
			domainList[value.Domain] = value
		}
		sslClient := ssl.CreateNewSSL(&conf)
		// 查询用户证书或者订单列表
		resp, err := sslClient.ListUserCertificate(1, 500, "CERT", "")
		if resp.TotalCount >= 1 {
			replaceDomainSSL := make(map[string]string, 0)
			for _, value := range resp.CertificateOrderList {
				if pdVal, ok := domainList[value.CommonName]; ok {
					expireDate := time.Now().Add(time.Duration(10) * time.Hour * 24).Local().Format("2006-01-02") // 10天
					if val, check := replaceDomainSSL[value.CommonName]; check {
						if val >= value.EndDate {
							continue
						}
					}
					if pdVal.OldEndDate <= expireDate {
						replaceDomainSSL[value.CommonName] = value.EndDate
						certName := fmt.Sprintf("%v_%v", value.CommonName, value.EndDate)
						slb.SetSlb(slbId, value.CertificateId, certName, value.CommonName)
						pdVal.CertId = value.CertificateId
						pdVal.CertName = certName
						// 替换证书
						err = slb.ReplaceSSL(&pdVal)
						if err != nil {
							fmt.Println()
							fmt.Println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
							continue
						}
					}
				}
			}
		}
	}

}
