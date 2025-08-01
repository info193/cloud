package cdn

import (
	"cloud/config"
	"cloud/ssl"
	"errors"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cdn"
	"strconv"
	"time"
)

type CDN struct {
	config *config.Config
	client *cdn.Client
}

func CreateNewCDN(conf *config.Config) *CDN {
	// 1. 初始化客户端
	newConfig := sdk.NewConfig()
	// 账号凭证
	credential := credentials.NewAccessKeyCredential(conf.Ssl.AccessKeyId, conf.Ssl.AccessKeySecret)
	// CDN服务客户端
	cdnClient, err := cdn.NewClientWithOptions(conf.Slb.RegionId, newConfig, credential)
	if err != nil {
		fmt.Println("创建CDN客户端失败:", err)
		return nil
	}
	return &CDN{config: conf, client: cdnClient}
}

// 查询用户证书或者订单列表
func (l *CDN) Domains(page, limit int64, DomainStatus string) ([]config.CDNDomain, error) {
	describeUserDomainsRequest := cdn.CreateDescribeUserDomainsRequest()
	describeUserDomainsRequest.PageSize = requests.NewInteger64(limit)
	describeUserDomainsRequest.PageNumber = requests.NewInteger64(page)
	if DomainStatus != "" {
		describeUserDomainsRequest.DomainStatus = DomainStatus
	}

	response, err := l.client.DescribeUserDomains(describeUserDomainsRequest)
	if err != nil && response.IsSuccess() == true {
		fmt.Println("获取CDN域名证书列表失败")
		return nil, err
	}
	domainList := make([]config.CDNDomain, 0)
	for _, value := range response.Domains.PageData {
		certInfo, err := l.CertInfo(value.DomainName)
		if err != nil && certInfo.IsSuccess() == true {
			fmt.Println("查询CDN域名证书详情失败", err)
			continue
		}
		for _, val := range certInfo.CertInfos.CertInfo {
			certId, _ := strconv.ParseInt(val.CertId, 10, 64)
			startTime, _ := time.Parse(time.RFC3339, val.CertStartTime)
			endTime, _ := time.Parse(time.RFC3339, val.CertExpireTime)
			domainList = append(domainList, config.CDNDomain{Domain: value.DomainName, SslProtocol: value.SslProtocol, OldCertId: certId, OldCertName: val.CertName, OldStartDate: startTime.Format("2006-01-02"), OldEndDate: endTime.Format("2006-01-02")})
		}
	}
	return domainList, nil
}
func (l *CDN) CertInfo(domainName string) (*cdn.DescribeDomainCertificateInfoResponse, error) {
	describeDomainCertificateInfoRequest := cdn.CreateDescribeDomainCertificateInfoRequest()
	describeDomainCertificateInfoRequest.DomainName = domainName
	response, err := l.client.DescribeDomainCertificateInfo(describeDomainCertificateInfoRequest)
	if err != nil {
		fmt.Println("获取cdn证书信息")
		return nil, err
	}
	return response, nil
}

func (l *CDN) ReplaceSSL(domain *config.CDNDomain) error {
	setCdnDomainSMCertificateRequest := cdn.CreateSetCdnDomainSSLCertificateRequest()
	setCdnDomainSMCertificateRequest.DomainName = domain.Domain
	setCdnDomainSMCertificateRequest.CertName = domain.CertName
	setCdnDomainSMCertificateRequest.CertId = requests.NewInteger64(domain.CertId)
	setCdnDomainSMCertificateRequest.CertType = "cas"
	setCdnDomainSMCertificateRequest.SSLProtocol = domain.SslProtocol
	response, err := l.client.SetCdnDomainSSLCertificate(setCdnDomainSMCertificateRequest)
	if err != nil {
		fmt.Println(fmt.Sprintf("domain:%v，CDN SSL Replace error,err:%v", domain.Domain, err))
		return err
	}
	if !response.IsSuccess() {
		return errors.New(fmt.Sprintf("设置CDN域名%v证书失败", domain.Domain))
	}
	verifyCertDomain := ssl.VerifyCert(domain.Domain)
	if verifyCertDomain == nil {
		fmt.Println(fmt.Sprintf("domain:%v，CDN SSL Replace success,verifyCert error.", domain.Domain))
		return errors.New("verifyCert error")
	}
	fmt.Println(fmt.Sprintf("domain：%v，CertId：%v，CertName：%v，OldEndDate：%v，newEndDate：%v，verifyCert：success", domain.Domain, domain.CertId, domain.CertName, domain.OldEndDate, verifyCertDomain.EndDate))
	return nil
}
