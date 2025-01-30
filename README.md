# Amazon-Web-Services-Misconfiguration

The Cloud Misconfiguration Scanner is a Python-based tool designed to scan AWS services for security misconfigurations. It checks for publicly exposed resources, misconfigured IAM policies, and other potential vulnerabilities.

## Features

- **AWS EC2 Scanner**: Detects instances with public IPs.
- **S3 Scanner**: Identifies buckets with public access.
- **IAM Scanner**: Checks if MFA is enabled for users.
- **Risk Assessment**: Assigns risk scores based on severity.
- **Compliance Check**: Evaluates compliance with CIS, NIST, and PCI standards.
- **Reporting**: Generates CSV and JSON reports.

## Installation

Clone the repository and install the required dependencies:

```bash
 git clone https://github.com/yourusername/cloud-misconfig-scanner.git
 cd cloud-misconfig-scanner
 pip install -r requirements.txt
```

## AWS Credentials Setup

To scan AWS services, you **must** provide valid AWS credentials. The tool uses `boto3`, which supports multiple authentication methods:

### 1. **Using AWS CLI Configuration (Recommended)**

Run the following command and enter your AWS access and secret keys:

```bash
aws configure
```

This will store credentials in `~/.aws/credentials`.

### 2. **Using Environment Variables**

You can also set AWS credentials as environment variables:

```bash
export AWS_ACCESS_KEY_ID='your-access-key'
export AWS_SECRET_ACCESS_KEY='your-secret-key'
```

For Windows (PowerShell):

```powershell
$env:AWS_ACCESS_KEY_ID="your-access-key"
$env:AWS_SECRET_ACCESS_KEY="your-secret-key"
```

### 3. **Using IAM Roles (For AWS EC2, Lambda, etc.)**

If running on an AWS-hosted service, attach an IAM role with appropriate permissions (`AmazonEC2ReadOnlyAccess`, `AmazonS3ReadOnlyAccess`, etc.). `boto3` will automatically use the role.

## Running the Scanner

Run the scanner using:

```bash
python main.py
```

## Example Output

```
Compliance Status: {'CIS': False, 'NIST': False, 'PCI': False}
Risk Score: 17
Reports generated: report.csv, report.json
```

## Future Improvements

- **Advanced Visualization**: Use Plotly/D3.js for better reports.
- **Real-time Monitoring**: Integrate AWS CloudWatch/EventBridge.
- **Deployment**: Host the dashboard on AWS Elastic Beanstalk or Docker.

## License

This project is licensed under the MIT License. Feel free to contribute and improve security auditing for AWS environments!

