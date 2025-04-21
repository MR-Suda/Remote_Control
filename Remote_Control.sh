#!/bin/bash

# NETWORK RESEARCH | PROJECT: REMOTE CONTROL
# Student Name: Shimon
# Program Code: NX201
# Class Code: 7736/32
# Lecturer:

# Triggers cleanup if the user hits Ctrl+C or the script ends
trap cleanup INT TERM
trap exit_cleanup EXIT
function cleanup() {
	echo -e "\e[31m[!] Script interrupted. Stopping SSH, Nipe and other related processes...\e[0m" | tee -a "$logfile"
	stop_services
	echo
	echo -e "\e[33m[+] Cleanup done. Exiting safely.\e[0m" | tee -a "$logfile"
	sleep 5
	exit 1
}
function exit_cleanup() {
	if [[ "$?" -eq 0 ]]; then
		echo -e "Script finished normally. Cleaning up..." | tee -a "$logfile"
		stop_services
		echo -e "\e[32m[+] All clean. Goodbye.\e[0m" | tee -a "$logfile"
		sleep 5
	fi
}

function stop_services() {
	pkill -f "sshpass" >/dev/null 2>&1
	pkill -f "proxychains" >/dev/null 2>&1
	pkill -f "openvpn" >/dev/null 2>&1
	pkill -f "nmap" >/dev/null 2>&1
	pkill -f "tor" >/dev/null 2>&1
	pkill -f "perl" >/dev/null 2>&1
	[[ -d "$toolsdir/nipe" ]] && perl "$toolsdir/nipe/nipe.pl" stop >/dev/null 2>&1
}

# Restrict the user to run the script only with root privileges and checks for password.
function root() {

	
	if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root! Exiting..."
	echo
	sleep 2
	exit
	
	fi
	echo "=== You are root ==="
	echo
	read -sp "Enter your secure access password - " pass
	echo
	if [[ "$pass" == "mrsuda" ]]; then
		clear
		echo "===================================="
		echo -e "\e[32m          REMOTE CONTROL\e[0m"
		echo "===================================="
		echo
		sleep 2
		dir
	else
		echo -e "\e[31mIncorrect password. Exiting... - \e[0m"
		sleep 2
		
	exit
	fi
}

# Function to ask the user where to create a directory
function dir() {
	
    while true; do
        read -p "Enter the full path to store tools and log files - " path
        echo

        if [[ -d "$path" ]]; then
            break
        else
            read -p "The path '$path' does not exist. Do you want to create it? [y/n]: " ans
            echo
            if [[ "$ans" =~ ^[Yy]$ ]]; then
                mkdir -p "$path"
                echo -e "\e[32m[+] Path created: $path\e[0m"
                echo
                break
            else
                echo -e "\e[33m[!] Please enter a valid existing path.\e[0m"
                echo
            fi
        fi
    done

    read -p "Enter a name for your tools folder - " folder_name
    echo

    toolsdir="$path/$folder_name"
    mkdir -p "$toolsdir"
    logfile="$toolsdir/Remote_Control_Log.log"
    echo -e "\e[32m[+] Tools directory set to - \e[0m $toolsdir"
    echo
    echo -e "\e[32m[+] Scan results will be saved in - \e[0m $toolsdir"
    echo
    InstallDependencies
}

# Function to install dependencies
tools=("whois" "git" "nmap" "geoip-bin" "curl" "sshpass" "zip" )
function InstallDependencies() {
	
	current_date=$(date +"%d.%m.%y - %H:%M:%S")
	echo "Installing required dependencies..." | tee -a "$logfile"
	echo | tee -a "$logfile"
	for toolname in "${tools[@]}"; do
		dpkg -s "$toolname" >/dev/null 2>&1 ||
		echo -e "\e[35m[*]\e[0m -  Installing $toolname" &&
		apt-get install "$toolname" -y >/dev/null 2>&1
		echo -e "\e[33m[#]\e[0m - Installed: $toolname" | tee -a "$logfile"
	done  
	InstallNipe
}
	
# Function to install Nipe
function InstallNipe(){
	
	if ! [ -d "$toolsdir/nipe" ]; then
		echo -e "\e[35m[*]\e[0m - Installing Nipe..." | tee -a "$logfile"
		git clone https://github.com/htrgouvea/nipe "$toolsdir/nipe" >/dev/null 2>&1
		cd "$toolsdir/nipe" >/dev/null 2>&1 || exit
		cpan install Try::Tiny Config::Simple JSON -y >/dev/null 2>&1
		cpan install Config::Simple -y >/dev/null 2>&1
		cpan install Switch JSON LWP::UserAgent Config::Simple -y >/dev/null 2>&1
		perl nipe.pl install -y >/dev/null 2>&1
	fi
	echo -e "\e[33m[#]\e[0m - Nipe installed" | tee -a "$logfile"
	echo
	ACTIVATENIPE
}
	
# Function to activate Nipe
function ACTIVATENIPE(){
	
		perl "$toolsdir/nipe/nipe.pl" stop >/dev/null 2>&1
		perl "$toolsdir/nipe/nipe.pl" restart >/dev/null 2>&1
		perl "$toolsdir/nipe/nipe.pl" start >/dev/null 2>&1
		perl "$toolsdir/nipe/nipe.pl" status >/dev/null 2>&1
		sleep 2
		COUNTRY=$(perl nipe.pl status | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | xargs -I{} geoiplookup {} | awk '{print $NF}')
	
	if [[ "$COUNTRY" =~ "Israel" || "$COUNTRY" =~ "IL" ]]; then 
		echo -e "\e[31m[!] Anonymity check failed. Exiting...\e[0m" | tee -a "$logfile"
		echo | tee -a "$logfile"
	exit
	else
		echo -e "✔️ Spoofed country: \e[33m$COUNTRY\e[0m. Continuing..." | tee -a "$logfile"
		echo | tee -a "$logfile"
		sleep 5
	fi
	menu
}

# Function to ask the user which option they want to use
function menu(){
	
	
	clear
	echo "===================================="
	echo -e "\e[32m          REMOTE CONTROL\e[0m"
	echo "===================================="
	echo
	echo -e "Spoofed country ~ \e[33m$COUNTRY\e[0m"
	echo
	
	while true; do
		echo "1) Run Scan"
		echo "2) Exit"
		echo
		read -rp "Enter your choice - " choice
		echo
	case $choice in
		1) USERESIP ;;
		2) break ;;
		*) echo -e "\e[31m[!] Invalid input. Please enter 1 or 2.\e[0m"; echo ;;
	esac
	done
}

# Function to gather user input, establish a server connection, and perform a scan on the provided IP address.
function USERESIP(){

	# Function to validate IP address
	function validate_ip() {
		local ip=$1
		local stat=1
	if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
		IFS='.' read -r -a ip_array <<< "$ip"
		[[ ${ip_array[0]} -le 255 && ${ip_array[1]} -le 255 && ${ip_array[2]} -le 255 && ${ip_array[3]} -le 255 ]] && stat=0
	fi
	return $stat
    }
    
    while true; do
        read -p "Enter the remote server's IP address - " uip
        if validate_ip "$uip"; then
            break
        else
            echo -e "\e[31m[!] Invalid IP address. Try again.\e[0m"
        fi
    done
	while true; do
		read -p "Enter the target IP address to scan - " iptoscan
	if validate_ip "$iptoscan"; then
	break
	else
		echo -e "\e[31m[!] Invalid IP address. Try again.\e[0m"
	fi
	done
	read -p "Enter the remote server's username - " uid
	read -p "Enter the remote server's password - " paswd
	echo
	
	# Checks SSH connectivity
	ssh_output=$(sshpass -p "$paswd" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$uid@$uip" "echo ok" 2>&1)
	if [[ "$ssh_output" =~ "Permission denied" ]]; then
		echo -e "\e[31m[!] SSH - Invalid credentials.\e[0m" | tee -a "$logfile"
		echo
	elif [[ "$ssh_output" =~ "Connection refused" ]]; then
		echo -e "\e[31m[!] SSH - Connection refused. Possibly blocked or not running.\e[0m" | tee -a "$logfile"
		echo
	elif [[ "$ssh_output" =~ "Connection timed out" ]]; then
		echo -e "\e[31m[!] SSH - Timeout. The server may be unreachable or blocking the connection.\e[0m" | tee -a "$logfile"
		echo
	elif [[ "$ssh_output" =~ "ok" ]]; then
		echo -e "\e[32m[+] SSH connection verified.\e[0m" | tee -a "$logfile"
		echo
	else
		echo -e "\e[33m[?] SSH returned unexpected response:\e[0m $ssh_output" | tee -a "$logfile"
		echo
	fi
	
	COUNTRYA=$(whois "$uip" | grep -i country | awk '{print $NF}')
	UPTIME=$(sshpass -p "$paswd" ssh -o StrictHostKeyChecking=no "$uid"@"$uip" 'uptime -p')
	echo "The server $uip is from $COUNTRYA and $UPTIME" | tee -a "$logfile"
	echo
	echo "Creating directory to store scan output..." | tee -a "$logfile"
	echo
	echo "Choose scan type -"
	echo
	echo "1) Quick"
	echo "2) Full (0-65535)"
	echo "3) Service/version detection"
	echo "4) OS detection (may take longer and require root)"
	echo
	read -p "Your choice - " scan_type
	echo
	
	case $scan_type in
		1) nmap_flags="-T4" ;;
		2) nmap_flags="-p- -T4" ;;
		3) nmap_flags="-sV -T4" ;;
		4) nmap_flags="-O -T4" ;;
		*) echo "Invalid option. Defaulting to quick."; nmap_flags="-T4" ;;
	esac
		sshpass_log_timestamp=$(date +"%d.%m.%y - %H:%M:%S")
		echo "========= SCAN STARTED - $sshpass_log_timestamp =========" | tee -a "$toolsdir/nmapscan.txt"
		echo "========= SCAN STARTED - $sshpass_log_timestamp =========" >> "$toolsdir/whoisscan.txt"
		echo "========= SCAN STARTED - $sshpass_log_timestamp =========" >> "$logfile"
		echo "Scans will be saved to $toolsdir/nmapscan.txt and whoisscan.txt" >> tee -a "$logfile"
		echo | tee -a "$logfile"
		sshpass -p "$paswd" ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR "$uid"@"$uip" "nmap $nmap_flags $iptoscan" >> "$toolsdir/nmapscan.txt"
		sleep 2
		sshpass -p "$paswd" ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR "$uid"@"$uip" "whois $iptoscan" >> "$toolsdir/whoisscan.txt"
		echo "Scan completed - $(date '+%H:%M:%S')" | tee -a "$logfile"
		echo "Scan completed - $(date '+%H:%M:%S')" >> "$toolsdir/nmapscan.txt"
		echo "Scan completed - $(date '+%H:%M:%S')" >> "$toolsdir/whoisscan.txt"
		echo
		echo "Results saved to -" | tee -a "$logfile"
		echo
		echo "$toolsdir/whoisscan.txt" | tee -a "$logfile"
		echo "$toolsdir/nmapscan.txt" | tee -a "$logfile"
		echo
		sleep 5
		VIEWINFO
}

# Function to view the output of the scan commands. 
function VIEWINFO(){

	while true; do
		read -p "View WHOIS scan results? [y/n] - " ans
		echo
	if [[ "$ans" =~ ^[Yy]$ ]]; then
		echo "Displaying whois scan results..." | tee -a "$logfile"
		echo
		cat "$toolsdir"/whoisscan.txt
	break
	elif [[ "$ans" =~ ^[Nn]$ ]]; then
		echo "Skipping WHOIS scan results." | tee -a "$logfile"
		echo
	break
	else
		echo "Invalid input, please answer Y/y or N/n." | tee -a "$logfile"
		echo
	fi
	done
	while true; do
		read -p "View NMAP scan results? [y/n] - " answ
		echo
	if [[ "$answ" =~ ^[Yy]$ ]]; then
		echo "Displaying nmap scan results..." | tee -a "$logfile"
		echo
		cat "$toolsdir"/nmapscan.txt
		echo
	break
	elif [[ "$answ" =~ ^[Nn]$ ]]; then
		echo "Skipping NMAP scan results." | tee -a "$logfile"
		echo
	break
	else
		echo "Invalid input, please answer Y or N." | tee -a "$logfile"
		echo
	fi
	done
	while true; do
		read -p "Would you like to scan another IP address? [y/n] - " repeat
		echo
		if [[ "$repeat" =~ ^[Yy]$ ]]; then
			menu
		break
		elif [[ "$repeat" =~ ^[Nn]$ ]]; then
		break
		else
			echo "Invalid input. Please answer Y/y or N/n." | tee -a "$logfile"
			echo
		fi
	done
	zipping
}

# Function to zip the output files
function zipping(){
	
	read -p "Zip the scan folder for backup or sharing? [y/n] - " zip_choice
	echo
	if [[ "$zip_choice" =~ ^[Yy]$ ]]; then
		zipname="scan_report_$(date +%d.%m.%y_%H:%M:%S).zip"
		zip -r "$toolsdir/$zipname" "$toolsdir" >/dev/null 2>&1
		echo "✔️ Report zipped and saved to $toolsdir/$zipname"
		echo
	else
		echo "Skipping zip."
		echo
	fi
	summary_tldr
}

# TL;DR function
function summary_tldr() {
	
	echo -e "\e[36m========= ~ TL;DR SCAN SUMMARY ~ =========\e[0m"
	echo -e "🗺️ Remote Server Country - \e[32m$COUNTRYA\e[0m"
	echo -e "⏱️ Remote Server Uptime  - \e[32m$UPTIME\e[0m"
	echo -e "🌐 Scanned Target IPs - "
	grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$toolsdir/whoisscan.txt" | sort -u | while read -r ip; do
	echo -e "=== $ip ==="
	done
	echo -e "📍 Open Ports Found - "
	grep -i 'open' "$toolsdir/nmapscan.txt" | awk '{print $1, $2, $3}' | sort -u
	echo -e "\e[36m==========================================\e[0m"
	echo
	generate_pdf
}

# Create a PDF file if the user chooses to
function generate_pdf() {
	
	read -p "Generate a PDF report? [y/n] - " ans
	echo
	if [[ "$ans" =~ ^[Yy]$ ]]; then
		echo "Checking for required tools..."
		echo
		for tool in enscript ghostscript; do
		if ! dpkg -s "$tool" &> /dev/null; then
			echo -e "\e[33m[*] Installing $tool...\e[0m"
			echo
			apt-get install -y "$tool" >/dev/null 2>&1
		else
			echo -e "\e[32m[+] $tool installed.\e[0m"
			echo
		fi
		done
	
		report_txt="$toolsdir/report_summary.txt"
		pdf_name="$toolsdir/scan_report_$(date +%d-%m-%y_%H-%M).pdf"
		echo "Generating report summary..." | tee -a "$logfile"
		echo
		{
		echo "========= REMOTE CONTROL SCAN REPORT ========="
		echo "Date - $(date)"
		echo "User - $uid@$uip"
		echo "-------------------------------------------"
		echo "Remote server country - $COUNTRYA"
		echo "Remote server uptime - $UPTIME"
		echo
		echo "========= WHOIS RESULTS ========="
		cat "$toolsdir/whoisscan.txt"
		echo
		echo "========= NMAP RESULTS ========="
		cat "$toolsdir/nmapscan.txt"
		echo
		} > "$report_txt"
	
	if [[ ! -s "$report_txt" ]]; then
		echo -e "\e[31m[!] Report file is empty. PDF creation aborted.\e[0m"
	return
	fi	
		enscript -B -q -p - "$report_txt" --header="REMOTE CONTROL SCAN REPORT|Page $%|" | ps2pdf - "$pdf_name"
		echo -e "\e[32m[+]\e[0m PDF report saved as - $pdf_name"
		echo
	fi
	echo -e "\e[32mDONE\e[0m"
	echo
	sleep 5
	exit
}

# Executing the first function.
root
