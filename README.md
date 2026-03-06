# Secure Code Inspector
## Prerequisites
The following packages are required to run this python script:
* argparse
* groq
* langchain_core
* langchain_groq
* langchain_text_splitters
* mdutils
* pathlib

## How to run
1. Download or clone the repository
2. Install the dependencies by running the following command in the directory of the project

		pip install -r requirements.txt
	If it fails, or there is a conflict in package version, try this command instead
		
		pip install -r requirements_backup.txt
3. Run SCI.py in a command prompt with the appropriate arguments

___
<br>

| Argument  | Help |
| ------------- |:-------------:|
| -f, --file      | Scans a single file     |
| -p, --path      | Scans a directory     |
| -s, --subdirectories      | Enables recursive scan in Directory mode     |
| -c, --chunking      | Enables chunking     |

<br>

To scan a single file without chunking:

	python SCI.py -f routes/login.ts
<br>

To scan a single file with chunking:

	python SCI.py -f routes/login.ts -c
<br>

To scan a single directory's contents without chunking:

	python SCI.py -p routes
<br>

To scan a single directory's contents with chunking:

	python SCI.py -p routes -c
<br>

To scan a directory and its subdirectories without chunking:

	python SCI.py -p routes -s
<br>

To scan a directory and its subdirectories with chunking:

	python SCI.py -p routes -s -c
