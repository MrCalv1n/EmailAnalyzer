#!/usr/bin/env python3

#EmailAnalyzer.py (python3 script) 
#by André Calvinho (aka MrCalv1n and calv1n)

#Extracts IoCs (emails, IPs, URLs, attachments,...) from .msg and .eml files.
#
#Currently, it also has support to expand shorted URLs and to scan attached files and URLs against VirusTotal.
#
#You need a VirusTotal API to use this feature.
#
#Please note that it doesn't upload any files to VirusTotal, it only checks if there is a match with known hashes 
#(so don't worry about exfiltrating sensitive files ;-) ). It also doesn't visit the expanded URL webpage, it only performs 
#some checks against the short url site provider.

import extract_msg
from eml_parser import eml_parser
import sys
import re
import os
import base64
import magic
import argparse
from pprint import pprint
from virus_total_apis import PublicApi as VirusTotalPublicApi
import errno
import json
import shutil, glob
import outlookmsgfile
import requests
import hashlib
import time #remove if not needed

def remove_duplicate_lines(input_file, output_file):
    lines_seen = set() # holds lines already seen
    outfile = open(output_file, "w")
    for line in open(input_file, "r"):
        if line not in lines_seen: # not a duplicate
            outfile.write(line)
            lines_seen.add(line)
    outfile.close()

def eml_parser_func(input_file, output_dir):
    # where to save attachments to
    outpath = output_dir + 'tmp'

    m = eml_parser.decode_email(input_file, include_attachment_data=True)

    for message in m['attachment']:

        filename = message['filename']

        filename = os.path.join(outpath, filename)
        if not os.path.exists(os.path.dirname(filename)):
            try:
                os.makedirs(os.path.dirname(filename))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        print('\tWriting attachment: {}'.format(filename))
        with open(filename, 'wb') as a_out:
            a_out.write(base64.b64decode(message['raw']))

    with open(input_file,'rt') as file:
        value = file.read()
        parsed_founds(value, output_dir)

    clean_duplicates(output_dir)

    moveAllFilesinDir(output_dir + "tmp/", output_dir + "extracted-attachments/")

def parsed_founds(src_file, output_dir):

    with open('confs/rules.json') as json_file:
        regex_list = json.load(json_file)

    for file, regex in regex_list['rules'].items():
        match = re.findall(regex,str(src_file))

        with open('confs/whitelist.txt', 'rt') as f:
            whitelist = f.readlines()

        #Write down the extracted field
        with open(output_dir + file + '_tmp.txt', 'at') as file:
            for m in match:
                res = [line for line in whitelist if(line.rstrip('\n') in m or line.rstrip('\n') in m[0])]
                if not res:
                    file.write(m[0] + '\n')

def msg_parser_func(input_file, output_dir):
    msg = extract_msg.Message(input_file)

    msg.save(False, False, False, False, None, output_dir + "tmp")

    email = outlookmsgfile.load(input_file)

    parsed_founds(email, output_dir)
    parsed_founds(msg.header, output_dir)
    parsed_founds(msg.body, output_dir)

    clean_duplicates(output_dir)

    moveAllFilesinDir(output_dir + "tmp/", output_dir + "extracted-attachments/")

def moveAllFilesinDir(srcDir, dstDir):
    if not os.path.exists(dstDir):
        os.makedirs(dstDir)
    # Check if both the are directories
    if os.path.isdir(srcDir) and os.path.isdir(dstDir) :
        # Iterate over all the files in source directory
        for filePath in os.listdir(srcDir):
            # Move each file to destination Directory
            try:
                shutil.move(srcDir+filePath, dstDir);
            except:
                pass
        shutil.rmtree(srcDir)

    else:
        print("srcDir & dstDir should be Directories")

def clean_duplicates(output_dir):

    #Cleanup duplicate lines

    for file in os.listdir(output_dir):
         filename = str(os.fsdecode(output_dir + file))
         if "_tmp" in filename: 
            remove_duplicate_lines(filename, filename.replace('_tmp',''))
            os.remove(filename)
         else:
             continue

def logo():

    print("    ▓█████  ███▄ ▄███▓ ▄▄▄       ██▓ ██▓    ▄▄▄       ███▄    █  ▄▄▄       ██▓   ▓██   ██▓▒███████▒▓█████  ██▀███  ")
    print("    ▓█   ▀ ▓██▒▀█▀ ██▒▒████▄    ▓██▒▓██▒   ▒████▄     ██ ▀█   █ ▒████▄    ▓██▒    ▒██  ██▒▒ ▒ ▒ ▄▀░▓█   ▀ ▓██ ▒ ██▒")
    print("    ▒███   ▓██    ▓██░▒██  ▀█▄  ▒██▒▒██░   ▒██  ▀█▄  ▓██  ▀█ ██▒▒██  ▀█▄  ▒██░     ▒██ ██░░ ▒ ▄▀▒░ ▒███   ▓██ ░▄█ ▒")
    print("    ▒▓█  ▄ ▒██    ▒██ ░██▄▄▄▄██ ░██░▒██░   ░██▄▄▄▄██ ▓██▒  ▐▌██▒░██▄▄▄▄██ ▒██░     ░ ▐██▓░  ▄▀▒   ░▒▓█  ▄ ▒██▀▀█▄  ")
    print("    ░▒████▒▒██▒   ░██▒ ▓█   ▓██▒░██░░██████▒▓█   ▓██▒▒██░   ▓██░ ▓█   ▓██▒░██████▒ ░ ██▒▓░▒███████▒░▒████▒░██▓ ▒██▒")
    print("    ░░ ▒░ ░░ ▒░   ░  ░ ▒▒   ▓▒█░░▓  ░ ▒░▓  ░▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▒░▓  ░  ██▒▒▒ ░▒▒ ▓░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░")
    print("    ░ ░  ░░  ░      ░  ▒   ▒▒ ░ ▒ ░░ ░ ▒  ░ ▒   ▒▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░░ ░ ▒  ░▓██ ░▒░ ░░▒ ▒ ░ ▒ ░ ░  ░  ░▒ ░ ▒░")
    print("    ░   ░      ░     ░   ▒    ▒ ░  ░ ░    ░   ▒      ░   ░ ░   ░   ▒     ░ ░   ▒ ▒ ░░  ░ ░ ░ ░ ░   ░     ░░   ░ ")
    print("    ░  ░       ░         ░  ░ ░      ░  ░     ░  ░         ░       ░  ░    ░  ░░ ░       ░ ░       ░  ░   ░     ")
    print("                                                                              ░ ░     ░                        ")


def main():
    print("\033c");
    logo()
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-r", "--read-file", dest="input_file", help="reads a msg/eml file as input")
    group.add_argument("-R", "--read-directory", dest="input_dir", help="reads msg/eml files in a directory")
    parser.add_argument("-w", "--output-directory", dest="output_dir", help="specifies a directory as output")
    parser.add_argument("-vt", "--virus-total", action="store_true", help="Enables scanning of email attachments in VirusTotal")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    output_dir = str(os.getcwd()+'/')

    if args.output_dir:

        output_dir = args.output_dir

        if not output_dir.endswith("/"):
            output_dir = output_dir + "/"

        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

    if args.input_dir:

        for filepath in os.listdir(args.input_dir):

            fileType = magic.Magic().id_filename(filepath)

            if "Microsoft Outlook Message" in fileType:
                msg_parser_func(filepath, output_dir)
            elif "Unicode text" in fileType:
                eml_parser_func(filepath, output_dir)
            else:
                continue

    elif args.input_file:

        fileType = magic.Magic().id_filename(args.input_file)

        if "Microsoft Outlook Message" in fileType:
            msg_parser_func(args.input_file, output_dir)
        elif "Unicode text" in fileType:
            eml_parser_func(args.input_file, output_dir)
        else:
            print("File Type not supported!")
            exit()
    else:

        parser.print_help(sys.stderr)
        if os.path.exists(str(os.getcwd()+'/tmp/')):
            shutil.rmtree(str(os.getcwd()+'/tmp/'))
        sys.exit(1)

    if os.path.exists(str(os.getcwd()+'/__pycache__')):
        shutil.rmtree(str(os.getcwd()+'/__pycache__'))

    #Here we start the analysis of the parsed content

    #Check if shorturls exist, if so, expland them
    switch = False

    with open(output_dir + 'urls_tmp.txt','wt') as newurls_file:
        with open(output_dir + 'urls.txt','rt') as urls_file:
            with open('confs/shorturl-providers.txt','rt') as f:
                shorturlproviders = f.readlines()
                for line in urls_file:
                    for provider in shorturlproviders:
                        if provider.strip() in line.strip():
                            resp = expand_url(line.strip(),provider.strip())
                            newurls_file.write(line.strip() + ' (' + resp + ')\n')
                            switch = True
                            break
                        else:
                            switch = False
                    if (switch == False):
                        newurls_file.write(line)

    clean_duplicates(output_dir)

    if args.virus_total:

        API_KEY = open('confs/VirusTotal_api.key', 'r').readline().strip()

        vt = VirusTotalPublicApi(API_KEY)

        # traverse root directory, and list directories as dirs and files as files in the extracted attachments
        for root, dirs, files in os.walk(output_dir + "/extracted-attachments/"):
            for file in files:
                filePath = (os.path.join(root, file))
                hash_file = hashlib.sha256(str(filePath).encode('utf-8')).hexdigest()
                try:
                    response_code = 204
                    while response_code == 204:
                        resp = vt.get_file_report(hash_file)
                        response_code = resp['response_code']
                        if response_code == 204:
                            time.sleep(60)
                    if resp['results']['response_code'] == 1 and resp['results']['positives'] > 10:
                        os.rename(filePath,filePath+'_malware')

                except:
                    print("Error, can't connect to VirusTotal!")

        #now do the same to check urls 

        url_file = ""
        url_rule = ""
        ip_file = ""
        ip_rule = ""

        with open('confs/rules.json', 'r') as file:

            for line in file:
                if "http" in line:
                    url_file = line.split('"')[1] + '.txt'
                    url_rule = line.split('"')[3].replace('\\\\','\\')
                if "ip" in line:
                    ip_file = line.split('"')[1] + '.txt'
                    ip_rule = line.split('"')[3].replace('\\\\','\\')


        with open(output_dir + 'malware_urls.txt','at') as w_file:
            with open(output_dir + url_file,'r') as r_file:
                VT_report(vt, r_file, w_file, url_rule, "url")
            with open(output_dir + ip_file,'r') as r_file:
                VT_report(vt, r_file, w_file, url_rule, "ip")
                
        #Remove malware_urls.txt file if empty
        if os.stat(output_dir + 'malware_urls.txt').st_size == 0:
            os.remove(output_dir + 'malware_urls.txt')

                            
    print("Done! Check out the output directory to see the results.")   
    
def VT_report(vt, r_file, w_file, rule, type):
    for line in r_file:
        match = re.findall(rule,line.strip())
        for m in match:
            try:
                response_code = 204
                while response_code == 204:
                    if type == "url":
                        resp = vt.get_url_report(m[0])
                    if type == "ip":
                        resp = vt.get_ip_report(m[0])
                    response_code = resp['response_code']
                    if response_code == 204:
                        time.sleep(60)

                if resp['results']['response_code'] == 1 and resp['results']['positives'] > 0:
                    w_file.write(m[0] + '\n')
            except:
                print("Error, can't connect to VirusTotal!")

def expand_url(url, provider):
    while provider in url:
        resp = requests.get(url, allow_redirects=False)
        url = resp.headers['Location']
    return url

if __name__ == "__main__":
    main()
