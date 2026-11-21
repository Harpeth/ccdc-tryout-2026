#!/usr/bin/env bash
# Fake scoring engine for the Linux jumpbox. Checks every scored service every 30 s
# and prints only CHANGES (UP -> DOWN, DOWN -> UP), so a firewall or password mistake shows up at once.
#
#   ./scorecheck.sh <team#> [domain]       e.g.  ./scorecheck.sh 7 team7.local
#   Log: ./score-<team>.log
#
# Needs: nc, dig (or nslookup), curl. smbclient is optional.
# These are rough checks (port open / basic answer). The real scoring engine may also log in or check content.

TEAM="${1:?usage: $0 <team#> [ad-domain]}"
DOMAIN="${2:-}"
NET="192.168.$TEAM"
LOG="score-$TEAM.log"
declare -A STATE

tcp()  { nc -z -w 3 "$1" "$2" >/dev/null 2>&1; }
dnsq() {  # any real answer (even NXDOMAIN) means the DNS service is alive; timeout/REFUSED means down
  if command -v dig >/dev/null; then
    dig +time=2 +tries=1 @"$1" "${2:-localhost}" A 2>/dev/null | grep -q 'status: NOERROR\|status: NXDOMAIN'
  else
    nslookup -timeout=2 -retry=1 "${2:-localhost}" "$1" 2>&1 | grep -q 'Name:\|NXDOMAIN'
  fi
}
http() { curl -sk -m 4 -o /dev/null "$1"; }
smb()  { if command -v smbclient >/dev/null; then smbclient -L "//$1" -N -m SMB3 >/dev/null 2>&1 || tcp "$1" 445; else tcp "$1" 445; fi; }

check() {  # name, command...
  local name="$1"; shift
  if "$@"; then s=UP; else s=DOWN; fi
  if [[ "${STATE[$name]}" != "$s" ]]; then
    local c; [[ $s == UP ]] && c='\e[32m' || c='\e[31m'
    printf "%s  ${c}%-5s\e[0m %s\n" "$(date +%T)" "$s" "$name" | tee -a "$LOG"
    STATE[$name]=$s
  fi
}

echo "Watching team $TEAM ($NET.0/24). Ctrl+C to stop. Changes go to $LOG"
while true; do
  # ctrl-rm .86 - DC
  check "ctrl-rm  DNS"          dnsq "$NET.86" "$DOMAIN"
  check "ctrl-rm  LDAP 389"     tcp  "$NET.86" 389
  check "ctrl-rm  Kerberos 88"  tcp  "$NET.86" 88
  check "ctrl-rm  SMB 445"      tcp  "$NET.86" 445
  check "ctrl-rm  RDP 3389"     tcp  "$NET.86" 3389
  # certified .109 - ADCS + shares
  check "certified SMB share"   smb  "$NET.109"
  check "certified certsrv web" http "http://$NET.109/certsrv/"
  check "certified RDP 3389"    tcp  "$NET.109" 3389
  # chris .78 - device management
  check "chris    RDP 3389"     tcp  "$NET.78" 3389
  check "chris    HTTP(S)"      bash -c "curl -sk -m 4 -o /dev/null https://$NET.78 || curl -s -m 4 -o /dev/null http://$NET.78 || nc -z -w3 $NET.78 8530"
  # comms .99 - mail
  check "comms    SMTP 25"      tcp  "$NET.99" 25
  check "comms    IMAP 143"     tcp  "$NET.99" 143
  # lookup .23 - DNS
  check "lookup   DNS"          dnsq "$NET.23" "$DOMAIN"
  # Linux-side hosts (your teammates' boxes, but good to know)
  check "sting    HTTP"         http "http://$NET.53"
  check "whale    HTTP"         http "http://$NET.11"
  check "andie    HTTP"         http "http://$NET.40"
  # Remote Access everywhere (RDP or SSH)
  for h in 86 109 78 99 23 53 11 40; do
    check "$NET.$h  remote (3389/22/5985)" bash -c "nc -z -w3 $NET.$h 3389 || nc -z -w3 $NET.$h 22 || nc -z -w3 $NET.$h 5985"
  done
  sleep 30
done
