# FUNCTIONAL OVERVIEW

This tool written in Go language can automatically perform the following operations:
1. Monitor the expiration time of SSL certificates for specified domains
2. Automatically apply for a new certificate when the certificate is about to expire
3. Download new certificate file
4. Update the new certificate to Alibaba Cloud related services (OSS, SLB, CDN)

# Functional Features
1. Automated Certificate Lifecycle Management
2. Support Alibaba Cloud multi service certificate updates
3. Check the status of certificates
4. Self signed or third-party SSL certificate upload management

# INSTALLATION REQUIREMENTS
 - Go 1.21 or higher version
 - Alibaba Cloud account and API access permissions
 - The following Alibaba Cloud service access permissions:
   - SSL Certificate Service
   - OSS
   - SLB
   - CDN


# certificate store
The newly applied certificate will be saved in the certificate directory

Certificate file naming format:< Domain Name >. pem and< Domain Name >. key

# Usage
```
 go run ssl.go # Verify the certificate that is about to expire and regenerate it for upload
 go run oss.go # Verify the certificate that is about to expire and replace it
 go run slb.go # Verify the certificate that is about to expire and replace it
 go run cdn.go # Verify the certificate that is about to expire and replace it
```
