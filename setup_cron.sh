#!/bin/bash

EXECUTABLE_PATH="$(pwd)/nmap_scanner.py"

if [ ! -f "$EXECUTABLE_PATH" ]; then
    echo "Error: Missing file $EXECUTABLE_PATH"
    exit 1
fi

read -r -p "When would you launch nmap_scanner? [HH:MM] " SCHEDULED_TIME

if [[ ! $SCHEDULED_TIME =~ ^[0-9]{2}:[0-9]{2}$ ]]; then
    echo "Bad time format, use HH:MM"
    exit 1
fi

echo "Select day of the week to schedule the scan:"
echo "0) Sunday"
echo "1) Monday"
echo "2) Tuesday"
echo "3) Wednesday"
echo "4) Thursday"
echo "5) Friday"
echo "6) Saturday"
read -r -p "Enter a number [0-6]: " WEEKDAY

if [[ ! $WEEKDAY =~ ^[0-6]$ ]]; then
    echo "Invalid day of the week. Please enter a number between 0 and 6."
    exit 1
fi


HOUR=$(echo "$SCHEDULED_TIME" | cut -d':' -f1)
MINUTE=$(echo "$SCHEDULED_TIME" | cut -d':' -f2)

read -r -p "Target IP (e.g. 192.168.1.0/24,192.168.1.2): " TARGETS

read -r -p "IP to exclude (leave empty if it's the case, e.g. 192.168.1.1,192.168.1.2): " EXCLUSIONS

# build a temporary script for exporting ENVs
SANITIZED_TARGETS=${TARGETS//\//_}
CRON_SCRIPT="$(pwd)/nmap_cron_job_${SANITIZED_TARGETS}.sh"

cat <<EOF > "$CRON_SCRIPT"
#!/bin/bash
export MIN_RATE=500
export OUTPUT_FOLDER="/path/to/nmap_reports"
export LOG_DIR="/path/to/log/nmap_scanner"
export LOG_LEVEL=debug

/path/to/.venv/bin/python3 "$EXECUTABLE_PATH" -t "$TARGETS" -e "$EXCLUSIONS" >> "/var/log/nmap_scanner.log" 2>&1
EOF

chmod +x "$CRON_SCRIPT"

CRON_CMD="$MINUTE $HOUR * * $WEEKDAY $CRON_SCRIPT"
(crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -

echo "Scanner set up for $SCHEDULED_TIME using cron."
echo "Target: $TARGETS"
echo "Exclusions: $EXCLUSIONS"
echo "Temporary script was stored in $CRON_SCRIPT"
