#!/bin/bash
python scripts/sast-scan.py --server-url http://localhost:9000 --token your_sonar_token --project-key my_project --source-path . --output reports/sast-report.json
python scripts/dast-scan.py --api-key your_zap_key --target http://localhost:8080 --output reports/dast-report.json
python scripts/dependency-scan.py --snyk-token your_snyk_token --path . --output reports/dependency-report.json
python scripts/generate-report.py --input reports/*-report.json --output reports/security-report.html