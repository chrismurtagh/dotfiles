#! /bin/bash
#
# Firewall rules for gaz.retechnology.com
#

# vars
IPT=/sbin/iptables

# Flush old rules and old custom tables
echo " * flushing old rules"
$IPT --flush
$IPT --delete-chain

# Set default policies for all three default chains
echo " * setting default policies"
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT ACCEPT
$IPT -N WEBBL 
$IPT -N THRU 
$IPT -N LOGDROP 
$IPT -N BLACKLIST

# Enable free use of loopback interfaces
echo " * allowing loopback devices"
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# All TCP sessions should begin with SYN
echo " * setting all TCP connections to begin with SYN"
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -m comment --comment "Drop TCP connection not starting by SYN " -j DROP

# Allow established and related packets
echo " * allowing established and related packets"
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Get rid of an fragmented packets
echo " * denying fragmented packets"
$IPT -A INPUT -f -m comment --comment "Drop fragmented packets" -j DROP

# Port Scan Attacks
# Null Scans
echo " * blocking null scan attacks"
# Log scan
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall > Port scan"
# Drop and blacklist for 120 seconds IP of attacker
$IPT -A INPUT -p tcp --tcp-flags ALL NONE  -m recent --name blacklist_120 --set -m comment --comment "Drop / Blacklist Null scan" -j DROP

# Xmas Scan
echo " * blocking xmas scan attacks"
# Log attacks
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall > XMAS scan "
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall > XMAS-PSH scan "
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall > XMAS-ALL scan "
# Drop and blacklist for 120 seconds IP of attacker
$IPT -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m recent --name blacklist_120 --set  -m comment --comment "Drop / Blacklist Xmas / PSH scan" -j DROP # Xmas-PSH scan
$IPT -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -m recent --name blacklist_120 --set  -m comment --comment "Drop / Blacklist Xmas scan" -j DROP # Against nmap -sX (Xmas tree scan)
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -m recent --name blacklist_120 --set  -m comment --comment "Drop / Blacklist Xmas / All scan" -j DROP # Xmas All scan

# Fin scan
echo " * blocking fin scan attacks"
#Log attack
$IPT -A INPUT -p tcp --tcp-flags ALL FIN -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall > FIN scan "
# Drop and blacklist for 120 seconds IP of attacker
$IPT -A INPUT -p tcp --tcp-flags ALL FIN -m recent --name blacklist_120 --set  -m comment --comment "Drop / Blacklist FIN scan" -j DROP

# SYN scan and TCP connect scan
echo " * blocking syn and tpc connect scan attacks"
# log  probable sS and full connect tcp scan
$IPT -A INPUT -p tcp  -m multiport --dports 23,79 --tcp-flags ALL SYN -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix "Firewall > SYN scan trap:"
# blacklist for 120 seconds
$IPT -A  INPUT -p tcp  -m multiport --dports 23,79 --tcp-flags ALL SYN -m recent --name blacklist_120 --set -j DROP

# UDP scan
echo " * blocking empty udp scan"
# log probable sU UDP scan
$IPT -A INPUT -p udp  -m limit --limit 6/h --limit-burst 1 -m length --length 0:28 -j LOG --log-prefix "Firewall > 0 length udp "
$IPT -A INPUT -p udp -m length --length 0:28 -m comment --comment "Drop UDP packet with no content" -j DROP

# Check traffic for scriptkiddies
$IPT -A INPUT -j WEBBL

# Block static addresses
echo "blocking 194.61.0.210"
$IPT -A INPUT -s 194.61.0.210 -j DROP

# Allow CloudFlare CDN
#echo " * allowing CloudFlare CDN traffic"
#$IPT -A INPUT -s 199.27.128.0/21 -j ACCEPT
#$IPT -A INPUT -s 173.245.48.0/20 -j ACCEPT
#$IPT -A INPUT -s 103.21.244.0/22 -j ACCEPT
#$IPT -A INPUT -s 103.22.200.0/22 -j ACCEPT
#$IPT -A INPUT -s 103.31.4.0/22 -j ACCEPT
#$IPT -A INPUT -s 141.101.64.0/18 -j ACCEPT
#$IPT -A INPUT -s 108.162.192.0/18 -j ACCEPT
#$IPT -A INPUT -s 190.93.240.0/20 -j ACCEPT
#$IPT -A INPUT -s 188.114.96.0/20 -j ACCEPT
#$IPT -A INPUT -s 197.234.240.0/22 -j ACCEPT
#$IPT -A INPUT -s 198.41.128.0/17 -j ACCEPT
#$IPT -A INPUT -s 162.158.0.0/15 -j ACCEPT

# Pull down list of IP's and populate static blacklist
# wget http://www.wizcrafts.net/chinese-iptables-blocklist.txt
#
# if [ -f chinese-iptables-blocklist.txt ]; then
#    BLOCKDB="chinese-iptables-blocklist.txt"
#    IPTBL=$(grep -E "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" $BLOCKDB)
#    for i in $IPTBL
#    do
#       echo " * blocking chinese network $i"
#       $IPT -A WEBBL -s $i -j LOGDROP
#    done
# fi
#
# rm chinese-iptables-blocklist.txt
#
$IPT -A WEBBL -s 182.188.0.0/24 -j LOGDROP
$IPT -A WEBBL -j RETURN

# Check all other traffic for blacklist entiries
$IPT -A INPUT -j BLACKLIST

# Allow non blacklisted traffic THRU
$IPT -A INPUT -j THRU

# Create 1 minute IP Blacklist
echo " * createing dynamic IP Blacklist"
$IPT -A BLACKLIST -m recent --name blacklist_120 --update  --seconds 120 -m comment --comment "Drop packet from IP inserted in blacklist last 120 secs" -j DROP
#$IPT -A BLACKLIST -j RETURN
# $IPT rull to add ip to blacklist
#$IPT -A INPUT <IPTABLES FILTERING OPTIONS> --name blacklist_120 --set -j DROP
# list can be viewed:
# cat /proc/net/xt_recent/blacklist_120
# add ip to blacklist
# echo +192.168.0.2 > /proc/net/xt_recent/blacklist_120
# remove ip from blacklist
# echo -192.168.0.2 > /proc/net/xt_recent/blacklist_120

# Brute Force adversion
echo " * limiting connections to ssh to 6/minute"
$IPT -N SSH-FLOOD
$IPT -A THRU -p tcp --dport 22 -m state --state NEW -j SSH-FLOOD
# Limit packet rate to 2 per second with a 6 per second burst
$IPT -A SSH-FLOOD -m limit --limit 2/s --limit-burst 6 -m comment --comment "Limit SSH rate" -j RETURN
# Log flooders
$IPT -A SSH-FLOOD -m limit --limit 6/h --limit-burst 1 -j LOG --log-prefix "Firewall > Probable SSH flood "
# Ban flooders for 120 seconds
$IPT -A SSH-FLOOD -m recent --name blacklist_120 --set  -m comment --comment "Blacklist source IP" -j DROP

# D.D.O.S Attacks

# ICMP Flooding
echo " * blocking ICMP Flooding"
# Create chain dedicated to ICMP flood
$IPT -N ICMP-FLOOD
# Jump to that chain when ICMP  detected
$IPT -A THRU  -p icmp -j ICMP-FLOOD
# Get out of chain if packet rate for the same IP is below 4 per second with a burst of 8 per second
$IPT -A ICMP-FLOOD -m limit --limit 4/s --limit-burst 8  -m comment --comment "Limit ICMP rate" -j RETURN
# Log as flood when rate is higher
$IPT -A ICMP-FLOOD -m limit --limit 6/h --limit-burst 1 -j LOG --log-prefix "Firewall > Probable icmp flood "
# Blacklist IP for 120 seconds
$IPT -A ICMP-FLOOD -m recent --name blacklist_120 --set -m comment --comment "Blacklist source IP" -j DROP

# UDP Flooding
echo " * blocking UDP Flooding"
# Create chain for UDP flood
$IPT -N UDP-FLOOD
# Jump to chain if UDP
$IPT -A THRU  -p  udp -j UDP-FLOOD
# Limit UDP rate to 10/sec with burst at 20 (sometimes it is not enough, if you know a better average rate, let me know!)
$IPT -A UDP-FLOOD -m limit --limit 10/s --limit-burst 20  -m comment --comment "Limit UDP rate" -j RETURN
# Log as flood when rate is higher
$IPT -A UDP-FLOOD -m limit --limit 6/h --limit-burst 1 -j LOG --log-prefix "Firewall > Probable udp flood "
# Blacklist IP for 120 seconds
$IPT -A UDP-FLOOD -m recent --name blacklist_120 --set -m comment --comment "Blacklist source IP" -j DROP

# SYN Flooding
echo " * blocking SYN Flooding"
# Create syn-flood chain
$IPT -N SYN-FLOOD
# Jump into syn-flood chain when a syn packet is detected
$IPT -A THRU  -p tcp --syn -j SYN-FLOOD
# Limit packet rate to 8 per second with a 24 per second burst
$IPT -A SYN-FLOOD -m limit --limit 16/s --limit-burst 48 -m comment --comment "Limit TCP SYN rate" -j RETURN
# Log as flood when rate is higher
$IPT -A SYN-FLOOD -m limit --limit 48/h --limit-burst 8 -j LOG --log-prefix "Firewall > Probable syn flood "
# Blacklist IP for 120 seconds
$IPT -A SYN-FLOOD -m recent --name blacklist_120 --set  -m comment --comment "Blacklist source IP" -j DROP

# Log and Drop Chain
$IPT -A LOGDROP -j LOG --log-prefix "Chinese IP blocked "
$IPT -A LOGDROP -j DROP

# Open the following ports
echo " * allowing ssh on port 22"
$IPT -A THRU -p tcp --dport 22 -m state --state NEW -j ACCEPT

echo " * allowing http on port 80"
$IPT -A THRU -p tcp --dport 80 -m state --state NEW -j ACCEPT

echo " * allowing https on port 443"
$IPT -A THRU -p tcp --dport 443 -m state --state NEW -j ACCEPT

echo " * allowing nagios nrpe client connections on port 5666"
$IPT -A THRU -p tcp --dport 5666 -m state --state NEW -j ACCEPT

echo " * allowing ping responses and traceroutes"
$IPT -A THRU -p ICMP --icmp-type 8 -j ACCEPT
$IPT -A THRU -p ICMP --icmp-type 11 -j ACCEPT

echo " * logging and dropping everything else"
#$IPT -A THRU -j LOG --log-prefix "explisit drop all"
$IPT -A THRU -j DROP

# Save the settings
echo " * Saving settings"
/etc/init.d/iptables save
