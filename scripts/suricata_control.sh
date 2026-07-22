#!/bin/bash
case $1 in
    start)   sudo systemctl start suricata-iot; sleep 3; sudo systemctl status suricata-iot --no-pager | head -5 ;;
    stop)    sudo systemctl stop suricata-iot; echo "Stopped" ;;
    status)  sudo systemctl status suricata-iot --no-pager | head -10 ;;
    alerts)  sudo cat /var/log/suricata/fast.log /tmp/suricata/fast.log 2>/dev/null | tail -${2:-20} ;;
    stats)   sudo tail -30 /var/log/suricata/stats.log 2>/dev/null | grep -E "capture|decoder|detect|flow" ;;
    reload)  sudo kill -USR2 $(pidof suricata) 2>/dev/null && echo "Rules reloaded" || echo "Not running" ;;
    test)    sudo suricata -T -c /etc/suricata/suricata-iot.yaml -v 2>&1 | tail -5 ;;
    clear)   sudo truncate -s 0 /var/log/suricata/fast.log /var/log/suricata/eve.json /var/log/suricata/stats.log 2>/dev/null; echo "Logs cleared" ;;
    *)       echo "Usage: $0 {start|stop|status|alerts [N]|stats|reload|test|clear}" ;;
esac
