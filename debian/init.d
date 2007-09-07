#!/bin/sh

PATH=/sbin:/bin:/usr/sbin:/usr/bin

# for a chrooted server: "-u bind -t /var/lib/named"
# Don't modify this line, change or create /etc/default/bind9.
OPTIONS=""

test -f /etc/default/bind9 && . /etc/default/bind9

test -x /usr/sbin/rndc || exit 0

. /lib/lsb/init-functions
DISTRO=$(lsb_release -is 2>/dev/null || echo Debian)

case "$1" in
    start)
	log_daemon_msg "Starting domain name service..."

	modprobe capability >/dev/null 2>&1 || true

	# dirs under /var/run can go away on reboots.
	mkdir -p /var/run/bind/run
	chmod 775 /var/run/bind/run
	chown root:bind /var/run/bind/run >/dev/null 2>&1 || true

	if [ ! -x /usr/sbin/named ]; then
	    log_action_msg "named binary missing - not starting"
	    log_end_msg 1
	    exit 1
	fi
	if start-stop-daemon --start --quiet --exec /usr/sbin/named \
		--pidfile /var/run/bind/run/named.pid -- $OPTIONS; then
	    if [ -x /sbin/resolvconf ] ; then
		echo "nameserver 127.0.0.1" | /sbin/resolvconf -a lo
	    fi
	fi
	log_end_msg 0
    ;;

    stop)
	log_daemon_msg "Stopping domain name service..."
	if [ -x /sbin/resolvconf ]; then
	    /sbin/resolvconf -d lo
	fi
	/usr/sbin/rndc stop
	log_end_msg 0	
    ;;

    reload)
	log_daemon_msg "Reloading domain name service..."
	/usr/sbin/rndc reload
	log_end_msg 0
    ;;

    restart|force-reload)
	$0 stop
	sleep 2
	$0 start
    ;;
    
    *)
	log_action_msg "Usage: /etc/init.d/bind {start|stop|reload|restart|force-reload}"
	exit 1
    ;;
esac

exit 0
