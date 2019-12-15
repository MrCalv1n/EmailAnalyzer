[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python Versions](https://img.shields.io/pypi/pyversions/yt2mp3.svg)](https://pypi.python.org/pypi/yt2mp3/)


EmailAnalyzer
=============

Extracts IoCs (emails, IPs, URLs, attachments,...) from .msg and .eml files.

Currently, it also has support to expand shorted URLs and to scan attached files and URLs against VirusTotal.

You need a VirusTotal API to use this feature. 

Please note that it doesn't upload any files to VirusTotal, it only checks if there is a match with known hashes (so don't worry about exfiltrating sensitive files ;-) ).
It also doesn't visit the expanded URL webpage, it only performs some checks against the short url site provider.



Example usage
-----

**To use it as a command-line script:**

     python3 EmailAnalyzer.py -r example.msg

This will create several txt files with IoCs extracted (like Bro does) and a folder ("extracted-attachments") with the attached files.

```bash 
    ▓█████  ███▄ ▄███▓ ▄▄▄       ██▓ ██▓    ▄▄▄       ███▄    █  ▄▄▄       ██▓   ▓██   ██▓▒███████▒▓█████  ██▀███
    ▓█   ▀ ▓██▒▀█▀ ██▒▒████▄    ▓██▒▓██▒   ▒████▄     ██ ▀█   █ ▒████▄    ▓██▒    ▒██  ██▒▒ ▒ ▒ ▄▀░▓█   ▀ ▓██ ▒ ██▒
    ▒███   ▓██    ▓██░▒██  ▀█▄  ▒██▒▒██░   ▒██  ▀█▄  ▓██  ▀█ ██▒▒██  ▀█▄  ▒██░     ▒██ ██░░ ▒ ▄▀▒░ ▒███   ▓██ ░▄█ ▒
    ▒▓█  ▄ ▒██    ▒██ ░██▄▄▄▄██ ░██░▒██░   ░██▄▄▄▄██ ▓██▒  ▐▌██▒░██▄▄▄▄██ ▒██░     ░ ▐██▓░  ▄▀▒   ░▒▓█  ▄ ▒██▀▀█▄
    ░▒████▒▒██▒   ░██▒ ▓█   ▓██▒░██░░██████▒▓█   ▓██▒▒██░   ▓██░ ▓█   ▓██▒░██████▒ ░ ██▒▓░▒███████▒░▒████▒░██▓ ▒██▒
    ░░ ▒░ ░░ ▒░   ░  ░ ▒▒   ▓▒█░░▓  ░ ▒░▓  ░▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▒░▓  ░  ██▒▒▒ ░▒▒ ▓░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░
    ░ ░  ░░  ░      ░  ▒   ▒▒ ░ ▒ ░░ ░ ▒  ░ ▒   ▒▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░░ ░ ▒  ░▓██ ░▒░ ░░▒ ▒ ░ ▒ ░ ░  ░  ░▒ ░ ▒░
    ░   ░      ░     ░   ▒    ▒ ░  ░ ░    ░   ▒      ░   ░ ░   ░   ▒     ░ ░   ▒ ▒ ░░  ░ ░ ░ ░ ░   ░     ░░   ░
    ░  ░       ░         ░  ░ ░      ░  ░     ░  ░         ░       ░  ░    ░  ░░ ░       ░ ░       ░  ░   ░
                                                                              ░ ░     ░
usage: EmailAnalyzer.py [-h] [-r INPUT_FILE | -R INPUT_DIR] [-w OUTPUT_DIR]
                        [-vt]

optional arguments:
  -h, --help            show this help message and exit
  -r INPUT_FILE, --read-file INPUT_FILE
                        reads a msg/eml file as input
  -R INPUT_DIR, --read-directory INPUT_DIR
                        reads msg/eml files in a directory
  -w OUTPUT_DIR, --output-directory OUTPUT_DIR
                        specifies a directory as output
  -vt, --virus-total    Enables scanning of email attachments in VirusTotal

```

#TODO
------------

* Check for Windows OS compatibility;
* Customize the header fields for requests;
* Create HTML final report (summary report);
* Adding proxy support;
* ...

Installation
------------

Please make sure you have all the requirements installed before using this tool:

-  Pypi

       pip3 install -r requirements.txt

Credits
-------

`Joshua Tauberer (outlookmsgfile)`

`Matthew Walker (extract_msg)`

`GOVCERT.LU (eml_parser)`

