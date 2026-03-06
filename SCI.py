from output import save_json_report, save_md_report
from prompts import parse_file, second_pass
import argparse
import os
from langchain_text_splitters import Language, RecursiveCharacterTextSplitter
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="LLM-Based OWASP Security Scanner")

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-p", "--path", type=str, help="Path to the repository or directory to scan"
    )

    group.add_argument("-f", "--file", type=str,
                       help="Path to the file to scan")

    parser.add_argument(
        "-s", "--subdirectories", action="store_true", help="Scans subdirectories"
    )

    parser.add_argument(
        "-c", "--chunking", action="store_true", help="Chunks files before analysis"
    )

    args = parser.parse_args()

    if args.path:
        if not os.path.exists(args.path):
            print(f"Error: The path '{args.path}' does not exist.")
            return
        if os.path.isfile(args.path):
            print(f"Error: '{args.path}' is a file, use -f instead.")
            return
        if args.chunking:
            process_directory_c(args.path, args.subdirectories)
        else:
            process_directory(args.path, args.subdirectories)
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: The file '{args.file}' does not exist.")
            return
        if os.path.isdir(args.file):
            print(f"Error: '{args.file}' is a directory, use -p instead.")
            return
        ext = get_file_extension(args.file)
        if ext is None:
            print(f"Error: '{args.file}' has an unsupported file type.")
            return
        if args.chunking:
            process_file_c(args.file, True)
        else:
            process_file(args.file, True)
    return


def print_chunks(chunks, file_path):
    print(f"File: {file_path}\n")
    for index, chunk in enumerate(chunks):
        print(f"Chunk {index}:\n{chunk}\n\n")
    return


def chunk_file(file_path, ext):
    file = open(file_path, "r").read()
    python_splitter = RecursiveCharacterTextSplitter.from_language(
        language=ext, chunk_size=1000, chunk_overlap=100
    )
    chunks = python_splitter.split_text(file)
    return chunks


def process_file(file_path, single_file):
    ext = get_file_extension(file_path)
    if ext is None:
        return
    file = open(file_path, "r").read()
    result = parse_file(file, file_path)
    if single_file:
        save_json_report(result, "report.json")
        save_md_report(result, "report.md")
    return result


def process_file_c(file_path, single_file):
    ext = get_file_extension(file_path)
    results = []
    if ext is None:
        return
    chunks = chunk_file(file_path, ext)
    for chunk in chunks:
        result = parse_file(chunk, file_path)
        results.extend(result)
    for result in results:
        result["file"] = str(file_path)
    results2 = second_pass(results)
    if single_file:
        save_json_report(results2, "report.json")
        save_md_report(results2, "report.md")
    return results2


def process_directory(dir_path, recursive):
    base_dir = Path(dir_path)
    results = []
    if recursive:
        for path in base_dir.rglob("*"):
            if path.is_file():
                result = process_file(path, False)
                results.extend(result)
    elif not recursive:
        for path in base_dir.glob("*"):
            if path.is_file():
                result = process_file(path, False)
                results.extend(result)
    save_json_report(results, "report.json")
    save_md_report(results, "report.md")
    return


def process_directory_c(dir_path, recursive):
    base_dir = Path(dir_path)
    results = []
    if recursive:
        for path in base_dir.rglob("*"):
            if path.is_file():
                result = process_file_c(path, False)
                results.extend(result)
    elif not recursive:
        for path in base_dir.glob("*"):
            if path.is_file():
                result = process_file_c(path, False)
                results.extend(result)
    save_json_report(results, "report.json")
    save_md_report(results, "report.md")
    return


def get_file_extension(file_path):
    extension_map = {
        ".py": Language.PYTHON,
        ".js": Language.JS,
        ".ts": Language.TS,
        ".java": Language.JAVA,
        ".cpp": Language.CPP,
        ".c": Language.CPP,
        ".php": Language.PHP,
        ".html": Language.HTML,
    }
    ext = Path(file_path).suffix.lower()
    return extension_map.get(ext)


if __name__ == "__main__":
    main()
