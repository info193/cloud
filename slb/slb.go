package slb

import (
	"cloud/config"
	"cloud/ssl"
	"errors"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/slb"
	"strconv"
	"strings"
	"time"
)

type Slb struct {
	config        *config.Config
	client        *slb.Client
	slbId         string
	protocolHttps slb.ListenerInDescribeLoadBalancerListeners
	protocolHttp  slb.ListenerInDescribeLoadBalancerListeners
	id            int64
	name          string
	domain        string
}

type DomainSsl struct {
	CertId              string // 证书id
	CertName            string // 证书名
	Domain              string // 域名
	ServerCertificateId string // 域名使用的证书 ID
	StartDate           string
	EndDate             string
}

func CreateNewSlb(conf *config.Config) *Slb {
	// 1. 初始化客户端
	newConfig := sdk.NewConfig()
	// 2.账号凭证
	credential := credentials.NewAccessKeyCredential(conf.Slb.AccessKeyId, conf.Slb.AccessKeySecret)
	// SLB服务客户端
	slbClient, err := slb.NewClientWithOptions(conf.Slb.RegionId, newConfig, credential)
	if err != nil {
		fmt.Println("创建SLB客户端失败:", err)
		return nil
	}
	return &Slb{config: conf, client: slbClient}
}
func (l *Slb) SetSlb(slbId string, id int64, name string, domain string) *Slb {
	l.slbId = slbId
	l.id = id
	l.name = name
	l.domain = domain
	return l
}

func (l *Slb) Listeners() (*slb.DescribeLoadBalancerListenersResponse, error) {
	request := slb.CreateDescribeLoadBalancerHTTPSListenerAttributeRequest()
	request.Scheme = "https"
	request.LoadBalancerId = l.slbId
	request.ListenerPort = requests.NewInteger(443)

	describeRequest := slb.CreateDescribeLoadBalancerListenersRequest()
	describeRequest.Scheme = "https"

	loadBalancerIds := &[]string{l.slbId}
	describeRequest.LoadBalancerId = loadBalancerIds
	describeRequest.ListenerProtocol = "https"

	// 查询负载均衡监听列表详情
	response, err := l.client.DescribeLoadBalancerListeners(describeRequest)
	if err != nil {
		return nil, err
	}
	for _, listen := range response.Listeners {
		if listen.ListenerProtocol == "https" {
			l.protocolHttps = listen
		}
	}
	return response, nil
}
func (l *Slb) ReplaceSSL(domain *config.SlbDomain) error {
	// 上传新证书至slb
	uploadServerCertificateRequest := slb.CreateUploadServerCertificateRequest()
	uploadServerCertificateRequest.AliCloudCertificateId = strconv.FormatInt(domain.CertId, 10)
	uploadServerCertificateRequest.AliCloudCertificateName = domain.CertName
	uploadServerAliyunSSl, err := l.client.UploadServerCertificate(uploadServerCertificateRequest)
	if err != nil {
		return err
	}
	// 设置更新域名证书
	createSetDomainExtensionAttributeRequest := slb.CreateSetDomainExtensionAttributeRequest()
	createSetDomainExtensionAttributeRequest.DomainExtensionId = domain.DomainExtensionId
	createSetDomainExtensionAttributeRequest.ServerCertificateId = uploadServerAliyunSSl.ServerCertificateId
	response, err := l.client.SetDomainExtensionAttribute(createSetDomainExtensionAttributeRequest)
	if err != nil {
		fmt.Println(fmt.Sprintf("domain:%v，SLB SSL Replace error,err:%v", domain.Domain, err))
		return err
	}
	if !response.IsSuccess() {
		return errors.New(fmt.Sprintf("设置SLB域名%v证书失败", domain.Domain))
	}

	verifyCertDomain := ssl.VerifyCert(domain.Domain)
	if verifyCertDomain == nil {
		fmt.Println(fmt.Sprintf("domain:%v，SLB SSL Replace success,verifyCert error.", domain.Domain))
		return errors.New("verifyCert error")
	}

	fmt.Println(fmt.Sprintf("domain：%v，CertId：%v，CertName：%v，OldEndDate：%v，newEndDate：%v，ServerCertificateId：%v，verifyCert：success", domain.Domain, domain.CertId, domain.CertName, domain.OldEndDate, verifyCertDomain.EndDate, uploadServerAliyunSSl.ServerCertificateId))
	return nil
}

func (l *Slb) DomainExtensionList(ListenerPort int) ([]config.SlbDomain, error) {
	// 查询已添加的扩展域名
	domainExtensions := slb.CreateDescribeDomainExtensionsRequest()
	domainExtensions.LoadBalancerId = l.slbId
	domainExtensions.ListenerPort = requests.NewInteger(ListenerPort)
	domainLists, err := l.client.DescribeDomainExtensions(domainExtensions)
	if err != nil {
		return nil, err
	}
	domain := make([]config.SlbDomain, 0)
	domainSSL, err := l.DomainSSL("")
	if err != nil {
		return nil, err
	}
	if len(domainLists.DomainExtensions.DomainExtension) >= 1 {
		for _, value := range domainLists.DomainExtensions.DomainExtension {
			slbDomain := config.SlbDomain{Domain: value.Domain, DomainExtensionId: value.DomainExtensionId, ServerCertificateId: value.ServerCertificateId}
			if ssl, ok := domainSSL[value.Domain]; ok {
				slbDomain.OldCertId = ssl.CertId
				slbDomain.OldCertName = ssl.CertName
				slbDomain.OldStartDate = ssl.StartDate
				oldStartDate, _ := time.ParseInLocation("2006-01-02 15:04:05", ssl.StartDate, time.Local)
				slbDomain.OldStartDate = oldStartDate.Format("2006-01-02")
				oldEndDate, _ := time.ParseInLocation("2006-01-02 15:04:05", ssl.EndDate, time.Local)
				slbDomain.OldEndDate = oldEndDate.Format("2006-01-02")
				slbDomain.OldServerCertificateId = ssl.ServerCertificateId
			}
			if slbDomain.OldServerCertificateId == "" {
				splits := strings.Split(value.Domain, ".")
				splits[0] = "*"
				tempDomain := strings.Join(splits, ".")
				if ssl, ok := domainSSL[tempDomain]; ok {
					slbDomain.OldCertId = ssl.CertId
					slbDomain.OldCertName = ssl.CertName
					oldStartDate, _ := time.ParseInLocation("2006-01-02 15:04:05", ssl.StartDate, time.Local)
					slbDomain.OldStartDate = oldStartDate.Format("2006-01-02")
					oldEndDate, _ := time.ParseInLocation("2006-01-02 15:04:05", ssl.EndDate, time.Local)
					slbDomain.OldEndDate = oldEndDate.Format("2006-01-02")
					slbDomain.OldServerCertificateId = ssl.ServerCertificateId
				}
			}
			domain = append(domain, slbDomain)
		}
	}
	return domain, nil
}

//	func (l *Slb) DeleteSSL(certificateId string) (bool, error) {
//		deleteCACertificateRequest := slb.CreateDeleteCACertificateRequest()
//		deleteCACertificateRequest.RegionId = l.config.Slb.RegionId
//		//deleteCACertificateRequest.ServerCertificateId = certificateId
//		deleteCACertificateRequest.CACertificateId = certificateId
//		response, err := l.client.DeleteCACertificate(deleteCACertificateRequest)
//		//response, err := l.client.DeleteServerCertificate(deleteServerCertificateRequest)
//		if err != nil {
//			fmt.Println("删除slb证书失败")
//			return false, err
//		}
//		fmt.Println(fmt.Sprintf("Replace State：%v,requestId：%v,certificateId：%v,CertId：%v,CertName：%v,OldCertId：%v,OldCertName：%v,OldEndDate：%v", response.IsSuccess(), response.RequestId, certificateId))
//		return response.IsSuccess(), nil
//	}
func (l *Slb) DomainSSL(certificateId string) (map[string]DomainSsl, error) {
	describeCACertificatesRequest := slb.CreateDescribeServerCertificatesRequest()
	describeCACertificatesRequest.RegionId = l.config.Slb.RegionId
	//describeCACertificatesRequest.ServerCertificateId = certificateId
	caLists, err := l.client.DescribeServerCertificates(describeCACertificatesRequest)
	if err != nil {
		fmt.Println("获取slb域名证书失败")
		return nil, err
	}
	domainSsl := make(map[string]DomainSsl, 0)
	for _, value := range caLists.ServerCertificates.ServerCertificate {
		startTime, _ := time.Parse(time.RFC3339, value.CreateTime)
		endTime, _ := time.Parse(time.RFC3339, value.ExpireTime)

		var certId string
		if value.IsAliCloudCertificate == 1 {
			certId = value.AliCloudCertificateId
		}
		domainSsl[value.CommonName] = DomainSsl{CertId: certId, CertName: value.ServerCertificateName, Domain: value.CommonName, ServerCertificateId: value.ServerCertificateId, StartDate: startTime.Format("2006-01-02 15:04:05"), EndDate: endTime.Format("2006-01-02 15:04:05")}
	}
	return domainSsl, nil
}
func (l *Slb) ProtocolDomain() ([]config.SlbDomain, error) {
	var domain []config.SlbDomain
	var err error
	if l.protocolHttps.ListenerProtocol == "https" {
		domain, err = l.DomainExtensionList(l.protocolHttps.ListenerPort)
		if err != nil {
			fmt.Println("获取扩展域名列表失败")
			return nil, err
		}
	}

	return domain, nil
}
