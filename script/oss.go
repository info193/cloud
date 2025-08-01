package main

import (
	"cloud/config"
	"cloud/oss"
	"cloud/ssl"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"path/filepath"
	"strings"
	"time"

	//"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	//"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"os"
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
	ossExpireReplaceSSL(conf) // 即将过期证书替换
	//ossReplaceSSL(conf)
	//domain(conf) // 获取域名

	return
}
func domain(conf config.Config) {
	// 创建oss链接
	ossClient := oss.CreateNewOSS(&conf)
	for _, bucket := range conf.Oss.Bucket {
		ossClient.SetBucketName(bucket)
		ossDomain, err := ossClient.GetBucketDomain()
		if err != nil {
			fmt.Println("获取桶绑定域名失败", err)
		}

		for _, value := range ossDomain {
			//fmt.Println(value.Domain, value.CertIdentifierId, value.OldCertIdentifierId, value.OldStartDate, value.OldEndDate)
			verifyCert := ssl.VerifyCert(value.Domain)
			if verifyCert != nil {
				fmt.Println(fmt.Sprintf("------------------------------%v start----------------------------------", value.Domain))
				fmt.Println(fmt.Sprintf("bucketName:%v", bucket))
				fmt.Println(fmt.Sprintf("domain:%v", value.Domain))
				fmt.Println(fmt.Sprintf("certIdentifierId:%v", value.CertIdentifierId))
				fmt.Println(fmt.Sprintf("certIdentifierId:%v", value.OldCertIdentifierId))
				fmt.Println(fmt.Sprintf("startDate:%v", value.OldStartDate))
				fmt.Println(fmt.Sprintf("endDate:%v", value.OldEndDate))
				fmt.Println(fmt.Sprintf("InUseSSLStartDate:%v", verifyCert.StartDate))
				fmt.Println(fmt.Sprintf("InUseSSLEndDate:%v", verifyCert.EndDate))
				fmt.Println(fmt.Sprintf("------------------------------%v end----------------------------------", value.Domain))
				fmt.Println()
			}
		}
	}
}
func ossExpireReplaceSSL(conf config.Config) {

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

	// 创建oss链接
	ossClient := oss.CreateNewOSS(&conf)
	for _, bucket := range conf.Oss.Bucket {
		ossClient.SetBucketName(bucket)
		ossDomain, err := ossClient.GetBucketDomain()
		if err != nil {
			fmt.Println(fmt.Sprintf("get bucket:%v domain error:%v", bucket, err))
			break
		}
		domainList := make(map[string]config.OssDomain, 0)
		for _, value := range ossDomain {
			if _, oks := cerfLists[value.Domain]; oks {
				domainList[value.Domain] = value
			}
		}

		sslClient := ssl.CreateNewSSL(&conf)
		// 查询用户证书或者订单列表
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
					pdVal.OldCertIdentifierId = pdVal.OldCertIdentifierId
					pdVal.CertIdentifierId = fmt.Sprintf("%v-%v", value.CertificateId, conf.Oss.RegionId)
					//替换证书
					err = ossClient.ReplaceSSL(&pdVal)
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
func ossReplaceSSL(conf config.Config) {
	// 创建oss链接
	ossClient := oss.CreateNewOSS(&conf)
	ossClient.SetBucketName("admin-test")
	ossDomain, err := ossClient.GetBucketDomain()
	if err != nil {
		fmt.Println("获取桶绑定域名失败", err)
	}
	domainList := make(map[string]config.OssDomain, 0)
	for _, value := range ossDomain {
		domainList[value.Domain] = value
	}

	sslClient := ssl.CreateNewSSL(&conf)
	// 查询用户证书或者订单列表
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
				expireDate := time.Now().Add(time.Duration(10) * time.Hour * 24).Local().Format("2006-01-02") // 10天
				if pdVal.OldEndDate <= expireDate {
					pdVal.OldCertIdentifierId = pdVal.OldCertIdentifierId
					pdVal.CertIdentifierId = fmt.Sprintf("%v-%v", value.CertificateId, conf.Oss.RegionId)
					replaceDomainSSL[value.CommonName] = value.EndDate
					//替换证书
					err = ossClient.ReplaceSSL(&pdVal)
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
