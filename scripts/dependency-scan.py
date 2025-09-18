import argparse
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_snyk_scan(snyk_token: str, path: str = '.') -> Dict:
    logger.info("Starting Snyk dependency scan")
    try:
        subprocess.run(['snyk', 'auth', snyk_token], check=True, capture_output=True)
        result = subprocess.run(['snyk', 'test', '--json'], cwd=path, check=True, capture_output=True, text=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"Snyk scan failed: {e.stderr}")
        raise

def run_trivy_scan(path: str = '.') -> Dict:
    logger.info("Starting Trivy dependency scan")
    try:
        result = subprocess.run(['trivy', 'fs', '--format', 'json', '--no-progress', path], check=True, capture_output=True, text=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"Trivy scan failed: {e.stderr}")
        raise

def combine_results(snyk_results: Dict, trivy_results: Dict) -> Dict:
    combined = {
        'snyk': snyk_results,
        'trivy': trivy_results,
        'summary': {
            'total_vulns': len(snyk_results.get('vulnerabilities', [])) + len(trivy_results.get('Results', [{}])[0].get('Vulnerabilities', []))
        }
    }
    return combined

def main():
    parser = argparse.ArgumentParser(description='Dependency Security Scanner')
    parser.add_argument('--snyk-token', required=True, help='Snyk authentication token')
    parser.add_argument('--path', default='.', help='Path to scan')
    parser.add_argument('--output', required=True, help='Output JSON file path')

    args = parser.parse_args()

    try:
        snyk_results = run_snyk_scan(args.snyk_token, args.path)
        trivy_results = run_trivy_scan(args.path)
        combined_results = combine_results(snyk_results, trivy_results)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(combined_results, f, indent=2)

        logger.info(f"Dependency scan completed. Results saved to: {output_path}")

        if combined_results['summary']['total_vulns'] > 10:
            exit(1)  # Fail if too many vulns

    except Exception as e:
        logger.error(f"Dependency scan failed: {e}")
        exit(1)

if __name__ == '__main__':
    main()