# Security Scanning Pipeline

![Security Pipeline](assets/securitypipeline-trity.png)

## Overview
An enterprise-grade security scanning pipeline that integrates SAST, DAST, and dependency scanning tools into your CI/CD workflow. Built with modern security practices and automation in mind.

## Features
- **Static Analysis (SAST)**: SonarQube integration for code quality and security
- **Dynamic Analysis (DAST)**: OWASP ZAP for vulnerability scanning
- **Dependency Scanning**: Trivy and Snyk for software composition analysis
- **Automated Reporting**: Customizable security reports and dashboards
- **CI/CD Integration**: Jenkins pipeline and GitHub Actions support
- **Configurable Gates**: Flexible security thresholds and policies

## Prerequisites
- Docker Engine 20.10+
- Jenkins 2.375+ or GitHub Actions
- Python 3.8+
- Git

## Project Structure
```
security-scanning-pipeline/
├── jenkins/                      # Jenkins pipeline configurations
│   ├── Jenkinsfile
│   └── pipeline-config.yaml
├── github-actions/              # GitHub Actions workflows
│   └── security-scan.yml
├── docker/                      # Container configurations
│   ├── sonarqube/
│   ├── zap/
│   └── trivy/
├── scripts/                     # Automation scripts
│   ├── setup.sh
│   ├── sast-scan.py
│   ├── dast-scan.py
│   ├── dependency-scan.py
│   └── generate-report.py
├── config/                      # Tool configurations
│   ├── sonar-project.properties
│   ├── zap-baseline.conf
│   └── trivy-config.yaml
└── reports/                     # Report templates
    └── templates/
```

## Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/security-scanning-pipeline.git
cd security-scanning-pipeline
```

2. **Set up environment:**
```bash
# Create and edit .env file
cp .env.example .env

# Install dependencies
./scripts/setup.sh
```

3. **Configure security tools:**
```bash
# Example .env configuration
SONAR_TOKEN=your_sonar_token
SNYK_TOKEN=your_snyk_token
ZAP_API_KEY=your_zap_key
SLACK_WEBHOOK=your_slack_webhook
EMAIL_SMTP_SERVER=smtp.company.com
EMAIL_RECIPIENTS=security@company.com
```

4. **Run security scan:**
```bash
./scripts/run-security-scan.sh
```

## Configuration

### Security Gates
| Severity Level | Default Threshold | Description |
|----------------|------------------|-------------|
| Critical       | 0                | Must fix    |
| High          | 2                | Important   |
| Medium        | 5                | Should fix  |
| Low           | 10               | Optional    |

### Customization
Edit `config/pipeline-config.yaml` to customize:
- Scan parameters
- Security thresholds
- Notification settings
- Report formats

## Reports
Security scans generate comprehensive reports in multiple formats:

- **HTML Dashboard**: Interactive visualization
- **JSON API**: Machine-readable results
- **PDF Reports**: Compliance documentation
- **SARIF**: IDE integration
- **Custom**: Configurable templates

## Tool Configuration

### SonarQube
```yaml
sonar.projectKey=security-pipeline
sonar.sources=.
sonar.exclusions=**/tests/**
```

### OWASP ZAP
```yaml
scan:
  threshold: MEDIUM
  excludeUrls:
    - \.js$
    - \.css$
```

### Trivy
```yaml
scan:
  severity: HIGH,CRITICAL
  skip-dirs:
    - tests
    - docs
```

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License
MIT License - see LICENSE file for details.