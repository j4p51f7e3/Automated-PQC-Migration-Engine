import os

from scanner.parser import parse_file
from scanner.detector import detect_crypto


TEST_DIRECTORY = "test_repository"


def scan_repository(directory):
    total_files = 0
    total_findings = 0

    print()
    print("=" * 60)
    print("        PQC MIGRATION ENGINE")
    print("=" * 60)
    print()

    print(f"Scanning directory: {directory}")
    print()

    for root, directories, files in os.walk(directory):

        for filename in files:

            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(root, filename)

            total_files += 1

            print(f"[SCANNING] {file_path}")

            tree = parse_file(file_path)

            if tree is None:
                continue

            findings = detect_crypto(file_path, tree)

            for finding in findings:
                finding.display()

            total_findings += len(findings)

    print()
    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)

    print(f"Files scanned : {total_files}")
    print(f"Findings      : {total_findings}")

    print()


if __name__ == "__main__":
    scan_repository(TEST_DIRECTORY)