# NMAP SCANNER

## Description
Nmap Scanner is a tool written entirely in Python that helps with network scanning. It performs the following tasks in order:

1. Host discovery (no port scanning).
2. port scanning of live hosts
3. Exporting results in CSV and TXT formats.

This tool aims to orchestrate Nmap to scan only active hosts, avoiding wasted time and network noise. 

The tool comes with two Bash scripts that can be used to run the code immediately or to schedule the scan over the course of a week using cron.

## Usage
nmap-scanner can be used directly lanching the main python file (you need to be root):

```
$ sudo python3 nmap_scanner.py -h
usage: Nmap Scanner [-h] [-t TARGET] [-e EXCLUDE] [-p OUTPUT_PATH]

Automated nmap scanner using python

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
  -e EXCLUDE, --exclude EXCLUDE
  -p OUTPUT_PATH, --output_path OUTPUT_PATH
```
When the script starts, it scan the given target, taking into account exclusions, if given, and write the following files:

* target_tcp.csv
* target_udp.csv
* target_tcp.txt
* target_udp.txt

The output path can be specified by an ENV. If you don't do it, reports will be stored in: `/tmp/nmap_reports`.

If you prefer to use the guided run script, you can launch:

* `./setup_cron.sh`: setup a cron job
* `./run_now.sh`, run it immediately.

The two scripts launch the same procedure, the only thing that changes is the scheduling.

```
$ sudo ./setup_cron.sh 

When would you launch nmap_scanner? [HH:MM] 10:00
Select day of the week to schedule the scan:
0) Sunday
1) Monday
2) Tuesday
3) Wednesday
4) Thursday
5) Friday
6) Saturday
Enter a number [0-6]: 6
Target IP (e.g. 192.168.1.0/24,192.168.1.2): 192.168.1.0/24
IP to exclude (leave empty if it's the case, e.g. 192.168.1.1,192.168.1.2): 192.168.1.1
Scanner set up for 10:00 using cron.
Target: 192.168.1.1/24
Exclusions: 192.168.1.1
Temporary script was stored in /home/user/nmapScanner/nmap_cron_job_192.168.1.0_24.sh
```

The latter script will do two things:

* It stores a temporary bash script which will be executed by cron, with all the env variables set (which you can edit later)
* The planning of the cron job on the linux system

The script, while running, will write some logs in `/var/log/nmap_scanner` (you can specify a different path by the ENV `LOG_PATH`).

## Environment variables management
The tool uses the following environment variables:

1. NMAP_OPTIONS_UDP (default: "-sU -Pn -T4")
2. NMAP_OPTIONS_TCP (default: "-sS -Pn -T4")
3. MIN_RATE (default: None)
4. MAX_RATE (default: None)
5. OUTPUT_FOLDER (default: /tmp/nmap_reports)
6. LOG_DIR (default: /var/log/nmap_scanner)
7. LOG_LEVEL (default: info)

You can add a .env file to specify all of this env variables, or edit the bash files.

