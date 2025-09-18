import argparse
import json
import logging
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SonarQubeScanner:
    def __init__(self, server_url: str, token: str, project_key: str):
        self.server_url = server_url.rstrip('/')
        self.token = token
        self.project_key = project_key
        self.session = requests.Session()
        self.session.auth = (token, '')

    def run_scan(self, source_path: str = '.', additional_params: Optional[Dict] = None) -> Dict:
        """Execute SonarQube scan"""
        logger.info(f"Starting SonarQube scan for project: {self.project_key}")

        # Prepare scanner command
        scanner_cmd = [
            'sonar-scanner',
            f'-Dsonar.projectKey={self.project_key}',
            f'-Dsonar.sources={source_path}',
            f'-Dsonar.host.url={self.server_url}',
            f'-Dsonar.login={self.token}',
            f'-Dsonar.projectVersion={datetime.now().strftime("%Y%m%d_%H%M%S")}'
        ]

        # Add additional parameters
        if additional_params:
            for key, value in additional_params.items():
                scanner_cmd.append(f'-D{key}={value}')

        try:
            # Run scanner
            result = subprocess.run(
                scanner_cmd,
                capture_output=True,
                text=True,
                check=True
            )

            logger.info("SonarQube scan completed successfully")

            # Wait for analysis to complete
            task_id = self._extract_task_id(result.stdout)
            if task_id:
                self._wait_for_analysis(task_id)

            # Get scan results
            return self._get_scan_results()

        except subprocess.CalledProcessError as e:
            logger.error(f"SonarQube scan failed: {e}")
            logger.error(f"STDOUT: {e.stdout}")
            logger.error(f"STDERR: {e.stderr}")
            raise

    def _extract_task_id(self, output: str) -> Optional[str]:
        """Extract task ID from scanner output"""
        for line in output.split('\n'):
            if 'task?id=' in line:
                return line.split('task?id=')[1].split()[0]
        return None

    def _wait_for_analysis(self, task_id: str, timeout: int = 300) -> None:
        """Wait for SonarQube analysis to complete"""
        logger.info(f"Waiting for analysis completion (task: {task_id})")

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = self.session.get(
                    f'{self.server_url}/api/ce/task',
                    params={'id': task_id}
                )
                response.raise_for_status()

                task_data = response.json()
                status = task_data.get('task', {}).get('status')

                if status == 'SUCCESS':
                    logger.info("Analysis completed successfully")
                    return
                elif status == 'FAILED':
                    raise Exception(f"Analysis failed: {task_data}")
                elif status in ['PENDING', 'IN_PROGRESS']:
                    logger.info(f"Analysis in progress... ({status})")
                    time.sleep(10)
                else:
                    logger.warning(f"Unknown status: {status}")
                    time.sleep(10)

            except Exception as e:
                logger.error(f"Error checking analysis status: {e}")
                time.sleep(10)

        raise TimeoutError(f"Analysis did not complete within {timeout} seconds")

    def _get_scan_results(self) -> Dict:
        """Retrieve scan results from SonarQube"""
        try:
            # Get project measures
            measures_response = self.session.get(
                f'{self.server_url}/api/measures/component',
                params={
                    'component': self.project_key,
                    'metricKeys': 'vulnerabilities,security_hotspots,bugs,code_smells,coverage,duplicated_lines_density'
                }
            )
            measures_response.raise_for_status()
            measures_data = measures_response.json()

            # Get issues
            issues_response = self.session.get(
                f'{self.server_url}/api/issues/search',
                params={
                    'componentKeys': self.project_key,
                    'types': 'VULNERABILITY,SECURITY_HOTSPOT',
                    'ps': 500  # Page size
                }
            )
            issues_response.raise_for_status()
            issues_data = issues_response.json()

            # Process results
            results = {
                'project_key': self.project_key,
                'scan_timestamp': datetime.now().isoformat(),
                'measures': self._process_measures(measures_data),
                'issues': self._process_issues(issues_data),
                'summary': self._generate_summary(measures_data, issues_data)
            }

            return results

        except Exception as e:
            logger.error(f"Error retrieving scan results: {e}")
            raise

    def _process_measures(self, measures_data: Dict) -> Dict:
        """Process SonarQube measures"""
        measures = {}
        for measure in measures_data.get('component', {}).get('measures', []):
            metric = measure.get('metric')
            value = measure.get('value', '0')
            measures[metric] = value
        return measures

    def _process_issues(self, issues_data: Dict) -> List[Dict]:
        """Process SonarQube issues"""
        processed_issues = []

        for issue in issues_data.get('issues', []):
            processed_issue = {
                'key': issue.get('key'),
                'type': issue.get('type'),
                'severity': issue.get('severity'),
                'component': issue.get('component'),
                'line': issue.get('line'),
                'message': issue.get('message'),
                'rule': issue.get('rule'),
                'creation_date': issue.get('creationDate'),
                'status': issue.get('status')
            }
            processed_issues.append(processed_issue)

        return processed_issues

    def _generate_summary(self, measures_data: Dict, issues_data: Dict) -> Dict:
        """Generate scan summary"""
        measures = self._process_measures(measures_data)
        issues = issues_data.get('issues', [])

        severity_counts = {
            'BLOCKER': 0,
            'CRITICAL': 0,
            'MAJOR': 0,
            'MINOR': 0,
            'INFO': 0
        }

        for issue in issues:
            severity = issue.get('severity', 'INFO')
            severity_counts[severity] += 1

        return {
            'total_issues': len(issues),
            'vulnerabilities': int(measures.get('vulnerabilities', 0)),
            'security_hotspots': int(measures.get('security_hotspots', 0)),
            'bugs': int(measures.get('bugs', 0)),
            'code_smells': int(measures.get('code_smells', 0)),
            'coverage': float(measures.get('coverage', 0)),
            'duplicated_lines_density': float(measures.get('duplicated_lines_density', 0)),
            'severity_breakdown': severity_counts
        }


def main():
    parser = argparse.ArgumentParser(description='SAST Security Scanner')
    parser.add_argument('--tool', choices=['sonarqube'], default='sonarqube',
                        help='SAST tool to use')
    parser.add_argument('--server-url', required=True,
                        help='SonarQube server URL')
    parser.add_argument('--token', required=True,
                        help='Authentication token')
    parser.add_argument('--project-key', required=True,
                        help='Project key')
    parser.add_argument('--source-path', default='.',
                        help='Source code path to scan')
    parser.add_argument('--output', required=True,
                        help='Output file path')
    parser.add_argument('--format', default='json',
                        choices=['json', 'html'],
                        help='Output format')

    args = parser.parse_args()

    try:
        if args.tool == 'sonarqube':
            scanner = SonarQubeScanner(
                server_url=args.server_url,
                token=args.token,
                project_key=args.project_key
            )
            results = scanner.run_scan(args.source_path)

        # Save results
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if args.format == 'json':
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
        elif args.format == 'html':
            html_content = generate_html_report(results)
            with open(output_path, 'w') as f:
                f.write(html_content)

        logger.info(f"SAST scan completed. Results saved to: {output_path}")

        # Exit with appropriate code
        critical_issues = results['summary']['severity_breakdown']['CRITICAL']
        blocker_issues = results['summary']['severity_breakdown']['BLOCKER']

        if blocker_issues > 0 or critical_issues > 5:
            sys.exit(1)  # Fail build
        elif critical_issues > 0:
            sys.exit(2)  # Warning
        else:
            sys.exit(0)  # Success

    except Exception as e:
        logger.error(f"SAST scan failed: {e}")
        sys.exit(1)


def generate_html_report(results: Dict) -> str:
    """Generate HTML report from scan results"""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>SAST Security Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
            .summary { margin: 20px 0; padding: 15px; background: #ecf0f1; border-radius: 5px; }
            .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
            .metric { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .critical { color: #e74c3c; }
            .major { color: #f39c12; }
            .minor { color: #f1c40f; }
            .issues { margin: 20px 0; }
            .issue { margin: 10px 0; padding: 10px; border-left: 4px solid #3498db; background: #f8f9fa; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>SAST Security Scan Report</h1>
            <p>Project: {project_key}</p>
            <p>Scan Date: {scan_timestamp}</p>
        </div>

        <div class="summary">
            <h2>Summary</h2>
            <p>Total Issues: {total_issues}</p>
            <p>Vulnerabilities: {vulnerabilities}</p>
            <p>Security Hotspots: {security_hotspots}</p>
        </div>

        <div class="metrics">
            <div class="metric blocker">
                <h3>Blocker Issues</h3>
                <p>{blocker_count}</p>
            </div>
            <div class="metric critical">
                <h3>Critical Issues</h3>
                <p>{critical_count}</p>
            </div>
            <div class="metric major">
                <h3>Major Issues</h3>
                <p>{major_count}</p>
            </div>
            <div class="metric">
                <h3>Code Coverage</h3>
                <p>{coverage}%</p>
            </div>
        </div>

        <div class="issues">
            <h2>Security Issues</h2>
            {issues_html}
        </div>
    </body>
    </html>
    """

    # Generate issues HTML
    issues_html = ""
    for issue in results['issues'][:20]:  # Show first 20 issues
        issues_html += f"""
        <div class="issue">
            <strong>{issue['severity']}: {issue['message']}</strong>
            <p>File: {issue['component']} | Line: {issue.get('line', 'N/A')} | Rule: {issue['rule']}</p>
        </div>
        """

    summary = results['summary']
    severity = summary['severity_breakdown']

    return html_template.format(
        project_key=results['project_key'],
        scan_timestamp=results['scan_timestamp'],
        total_issues=summary['total_issues'],
        vulnerabilities=summary['vulnerabilities'],
        security_hotspots=summary['security_hotspots'],
        blocker_count=severity['BLOCKER'],
        critical_count=severity['CRITICAL'],
        major_count=severity['MAJOR'],
        coverage=summary['coverage'],
        issues_html=issues_html
    )


if __name__ == '__main__':
    main()