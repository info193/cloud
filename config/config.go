package config

type Config struct {
	Ssl struct {
		AccessKeyId     string `yaml:"accessKeyId"`
		AccessKeySecret string `yaml:"accessKeySecret"`
		RegionId        string `yaml:"regionId"`
		Package         struct {
			Phone    string `yaml:"phone"`
			Email    string `yaml:"email"`
			Username string `yaml:"username"`
		} `yaml:"package"`
	} `yaml:"ssl"`
	UploadSsl struct {
		AccessKeyId     string `yaml:"accessKeyId"`
		AccessKeySecret string `yaml:"accessKeySecret"`
		RegionId        string `yaml:"regionId"`
	} `yaml:"sslUpload"`
	Oss struct {
		AccessKeyId     string   `yaml:"accessKeyId"`
		AccessKeySecret string   `yaml:"accessKeySecret"`
		RegionId        string   `yaml:"regionId"`
		Bucket          []string `yaml:"bucket"`
	} `yaml:"oss"`
	Slb struct {
		AccessKeyId     string   `yaml:"accessKeyId"`
		AccessKeySecret string   `yaml:"accessKeySecret"`
		RegionId        string   `yaml:"regionId"`
		Slbs            []string `yaml:"slbs"`
	} `yaml:"slb"`
	Cdn struct {
		AccessKeyId     string `yaml:"accessKeyId"`
		AccessKeySecret string `yaml:"accessKeySecret"`
		RegionId        string `yaml:"regionId"`
	} `yaml:"cdn"`
}
