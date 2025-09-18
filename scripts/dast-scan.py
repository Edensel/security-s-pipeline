import argparse
import json
import logging
import time
from pathlib import Path
from typing import Dict

from zapv2 import ZAPv2

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ZAPScanner:
    def __init__(self, api_key: str, proxy_host: str = 'http://127.0.0.1:8080'):
        self.zap = ZAPv2(apikey=api_key, proxies={'http': proxy_host, 'https': proxy_host})

    def run_scan(self, target_url: str) -> Dict:
        logger.info(f"Starting DAST scan for target: {target_url}")

        # Access target to start session
        self.zap.urlopen(target_url)
        time.sleep(2)

        # Start spider
        scan_id = self.zap.spider.scan(url=target_url)
        logger.info(f"Spider scan ID: {scan_id}")
        while int(self.zap.spider.status(scan_id)) < 100:
            logger.info(f"Spider progress: {self.zap.spider.status(scan_id)}%")
            time.sleep(5)

        # Start active scan
        active_scan_id = self.zap.ascan.scan(url=target_url)
        logger.info(f"Active scan ID: {active_scan_id}")
        while int(self.zap.ascan.status(active_scan_id)) < 100:
            logger.info(f"Active scan progress: {self.zap.ascan.status(active_scan_id)}%")
            time.sleep(5)

        # Get alerts
        alerts = self.zap.core.alerts(baseurl=target_url)
        results = {
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': target_url,
            'alerts': alerts,
            'summary': self._generate_summary(alerts)
        }

        logger.info("DAST scan completed")
        return results

    def _generate_summary(self, alerts: list) -> Dict:
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            severity_counts[risk] += 1
        return {'total_alerts': len(alerts), 'severity_breakdown': severity_counts}

def main():
    parser = argparse.ArgumentParser(description='DAST Security Scanner using OWASP ZAP')
    parser.add_argument('--api-key', required=True, help='ZAP API key')
    parser.add_argument('--target', required=True, help='Target URL to scan')
    parser.add_argument('--output', required=True, help='Output JSON file path')

    args = parser.parse_args()

    try:
        scanner = ZAPScanner(api_key=args.api_key)
        results = scanner.run_scan(target_url=args.target)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

        logger.info(f"DAST scan results saved to: {output_path}")

        high_alerts = results['summary']['severity_breakdown']['High']
        if high_alerts > 0:
            exit(1)  # Fail if high severity found

    except Exception as e:
        logger.error(f"DAST scan failed: {e}")
        exit(1)

if __name__ == '__main__':
    main()