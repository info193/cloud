package config

type SlbDomain struct {
	RegionId               string // 区域
	CertId                 int64  // 新证书id
	CertName               string // 新证书名
	Domain                 string // 域名
	DomainExtensionId      string // 扩展域名 ID
	ServerCertificateId    string // 域名使用的证书 ID
	OldCertId              string // 原阿里证书id
	OldCertName            string // 原证书名
	OldStartDate           string // 原证书创建时间
	OldEndDate             string // 原证书过期时间
	OldServerCertificateId string // 原服务器证书ID
}

type OssDomain struct {
	CertIdentifierId    string // 新证书CertIdentifier  例如：19501333-cn-hangzhou
	OldCertIdentifierId string // 原证书CertIdentifier  例如：19501333-cn-hangzhou
	Domain              string // 域名
	OldStartDate        string // 原证书创建时间
	OldEndDate          string // 原证书过期时间
}

type CDNDomain struct {
	CertName     string // 证书名称
	CertId       int64  // 证书id
	Domain       string // 域名
	SslProtocol  string // HTTPS 证书是否启用。取值：on：启用。 off：不启用。
	OldStartDate string // 原证书创建时间
	OldEndDate   string // 原证书过期时间
	OldCertName  string // 证书名称
	OldCertId    int64  // 证书id
}

type VerifyCertDomain struct {
	Domain    string // 域名
	StartDate string // 证书创建时间
	EndDate   string // 证书过期时间
}
