package oss

import (
	"cloud/config"
	"cloud/ssl"
	"context"
	"errors"
	"fmt"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"log"
	"net/http"
	"os"
	"time"
)

type Oss struct {
	config     *config.Config
	client     *oss.Client
	bucketName string
}

func CreateNewOSS(conf *config.Config) *Oss {
	os.Setenv("OSS_ACCESS_KEY_ID", conf.Oss.AccessKeyId)
	os.Setenv("OSS_ACCESS_KEY_SECRET", conf.Oss.AccessKeySecret)
	// 加载默认配置并设置凭证提供者和区域
	cfg := oss.LoadDefaultConfig().
		WithCredentialsProvider(credentials.NewEnvironmentVariableCredentialsProvider()).
		WithRegion(conf.Oss.RegionId)
	// 创建OSS客户端
	client := oss.NewClient(cfg)
	return &Oss{config: conf, client: client}
}
func (l *Oss) SetBucketName(bucketName string) {
	l.bucketName = bucketName
}
func (l *Oss) GetBucketDomain() ([]config.OssDomain, error) {
	request := &oss.ListCnameRequest{
		Bucket: oss.Ptr(l.bucketName),
	}

	// 执行列出存储空间CNAME的操作
	result, err := l.client.ListCname(context.TODO(), request)
	if err != nil {
		log.Fatalf("failed to list bucket cname %v", err)
		return nil, err
	}

	domains := make([]config.OssDomain, 0)
	if len(result.Cnames) > 0 {
		for _, cnameInfo := range result.Cnames {
			// 解析字符串为time.Time对象，注意使用正确的布局字符串
			layout := "Jan 2 15:04:05 2006 GMT"
			startTime, _ := time.Parse(layout, *cnameInfo.Certificate.ValidStartDate)
			startDate := startTime.Local().Format("2006-01-02")
			endTime, _ := time.Parse(layout, *cnameInfo.Certificate.ValidEndDate)
			endDate := endTime.Local().Format("2006-01-02")
			domains = append(domains, config.OssDomain{Domain: *cnameInfo.Domain, OldCertIdentifierId: *cnameInfo.Certificate.CertId, OldStartDate: startDate, OldEndDate: endDate})
		}
	}

	return domains, nil
}
func (l *Oss) ReplaceSSL(domain *config.OssDomain) error {
	// 创建绑定自定义域名和证书的请求
	request := &oss.PutCnameRequest{
		Bucket: oss.Ptr(l.bucketName),
		BucketCnameConfiguration: &oss.BucketCnameConfiguration{
			Domain: oss.Ptr(domain.Domain), // 填写自定义域名
			CertificateConfiguration: &oss.CertificateConfiguration{
				CertId: oss.Ptr(domain.CertIdentifierId),
				//Certificate: oss.Ptr("-----BEGIN CERTIFICATE-----MIIFBzCCA++gT2H2hT6Wb3nwxjpLIfXmSVcV*****-----END CERT"),
				//PrivateKey:  oss.Ptr("-----BEGIN CERTIFICATE-----MIIFBzCCA++gT2H2hT6Wb3nwxjpLIfXmSVcV*****-----END CERTIFICATE-----"),
				Force: oss.Ptr(true),
			},
		},
	}

	// 执行绑定自定义域名和证书的操作
	result, err := l.client.PutCname(context.TODO(), request)
	if err != nil {
		log.Fatalf("failed to put bucket cname %v", err)
		return err
	}
	if result.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("设置OSS域名%v证书失败", domain.Domain))
	}

	verifyCertDomain := ssl.VerifyCert(domain.Domain)
	if verifyCertDomain == nil {
		fmt.Println(fmt.Sprintf("domain:%v，OSS SSL Replace success,verifyCert error.", domain.Domain))
		return errors.New("verifyCert error")
	}
	fmt.Println(fmt.Sprintf("domain：%v，OldCertificateId：%v，OldEndDate：%v，newEndDate：%v，NewCertificateId：%v，verifyCert：success", domain.Domain, domain.OldCertIdentifierId, domain.OldEndDate, verifyCertDomain.EndDate, domain.CertIdentifierId))
	return nil
}
