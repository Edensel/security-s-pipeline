import argparse
import glob
import json
import logging
from pathlib import Path

from json2html import json2html

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_html_report(input_files: list, output_path: str):
    combined_data = {}
    for file in input_files:
        with open(file, 'r') as f:
            data = json.load(f)
            key = Path(file).stem
            combined_data[key] = data

    html_content = """
<html>
<head><title>Security Scan Report</title></head>
<body>
<h1>Combined Security Scan Report</h1>
""" + json2html.convert(json=combined_data) + """
</body>
</html>
"""

    with open(output_path, 'w') as f:
        f.write(html_content)

    logger.info(f"Report generated at: {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Generate Security Report from JSON files')
    parser.add_argument('--input', required=True, help='Glob pattern for input JSON files, e.g., reports/*.json')
    parser.add_argument('--output', required=True, help='Output HTML file path')

    args = parser.parse_args()

    try:
        input_files = glob.glob(args.input)
        if not input_files:
            raise ValueError("No input files found")

        generate_html_report(input_files, args.output)

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        exit(1)

if __name__ == '__main__':
    main()