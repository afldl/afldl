import os
import hashlib
from collections import defaultdict

def calculate_md5(file_path, chunk_size=8192):
    """Calculate the MD5 checksum of a file."""
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
    return md5.hexdigest()

def find_duplicate_files(directory):
    """Find duplicate files in the given directory based on MD5 checksums."""
    # Dictionary to store file paths keyed by their MD5 checksums
    md5_dict = defaultdict(list)

    # Walk through the directory and calculate MD5 for each file
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                file_md5 = calculate_md5(file_path)
                md5_dict[file_md5].append(file_path)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")

    # Filter out unique files, leaving only duplicates
    duplicates = {md5: paths for md5, paths in md5_dict.items() if len(paths) > 1}

    return duplicates

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python script.py <directory>")
        sys.exit(1)

    directory_to_check = sys.argv[1]

    if not os.path.isdir(directory_to_check):
        print(f"The provided path '{directory_to_check}' is not a valid directory.")
        sys.exit(1)

    duplicates = find_duplicate_files(directory_to_check)

    if duplicates:
        print("Duplicate files found:")
        for md5, paths in duplicates.items():
            print(f"\nFiles with MD5 {md5}:")
            for path in paths:
                print(f" - {path}")
    else:
        print("No duplicate files found.")