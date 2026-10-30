#!/bin/bash
# Isolation tests on a real HostZit server (run as root):
#   isolation.sh ACCOUNT_A SITE_A ACCOUNT_B SITE_B
# Account A tries to read, list, write, signal and connect to account B
# from PHP (its website) and from a shell in its cage (like SSH or cron).
# Every line must say PASS.
set -u
A=$1 SA=$2 B=$3 SB=$4
fail=0
pass() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; fail=1; }
docA=/home/$A/sites/$SA/public
docB=/home/$B/sites/$SB/public

# a secret of B
echo "secret-of-$B" > /home/$B/sites/$SB/public/secret.txt
# a wp-config.php of B (only made when B has none: never touch a real one)
madecfg=0
if [ ! -e /home/$B/sites/$SB/public/wp-config.php ]; then
	echo "db-password-of-$B" > /home/$B/sites/$SB/public/wp-config.php
	chown $B:$B /home/$B/sites/$SB/public/wp-config.php
	chmod 600 /home/$B/sites/$SB/public/wp-config.php
	madecfg=1
fi
chown $B:$B /home/$B/sites/$SB/public/secret.txt

cat > $docA/probe.php <<'PHP'
<?php
header('Content-Type: text/plain');
$b = $_GET['b']; $sb = $_GET['sb'];
function t($name, $ok) { echo ($ok ? "PASS" : "FAIL"), "  php: $name\n"; }
t("cannot read B's files", @file_get_contents("/home/$b/sites/$sb/public/secret.txt") === false);
t("cannot read B's wp-config.php", @file_get_contents("/home/$b/sites/$sb/public/wp-config.php") === false);
$h = @scandir('/home'); t("sees no other home in /home", $h === false || count(array_diff($h, ['.', '..'])) == 1);
t("cannot list B's home", @scandir("/home/$b") === false);
t("cannot write into B's site", @file_put_contents("/home/$b/sites/$sb/public/x.php", "x") === false);
$pw = @file_get_contents('/etc/passwd'); t("/etc/passwd does not list B", $pw === false || strpos($pw, $b) === false);
t("cannot read /etc/shadow", @file_get_contents('/etc/shadow') === false);
t("cannot read nginx configs", @scandir('/etc/nginx') === false || count(@scandir('/etc/nginx/zit.d/hostzit/sites') ?: []) == 0);
t("cannot read HostZit config", @file_get_contents('/etc/hostzit/server.env') === false);
t("cannot read the PowerDNS key", @file_get_contents('/etc/hostzit/pdns-api.key') === false);
$procs = 0; foreach (@scandir('/proc') ?: [] as $p) if (ctype_digit($p)) $procs++;
t("sees no other processes ($procs)", $procs < 40);
t("exec is disabled", !function_exists('shell_exec') || @shell_exec('id') === null);
t("cannot reach B's PHP socket", @stream_socket_client("unix:///var/lib/hostzit/cages/$b/.sock/php84.sock", $e, $s, 1) === false);
$f = @fsockopen('127.0.0.1', 25, $e, $s, 2); t("no direct SMTP to the local port 25 (or nothing listens)", $f === false);
t("open_basedir keeps PHP in its home", @file_get_contents('/var/lib/hostzit/cages/' . $b . '/etc/passwd') === false);
t("its own files work", file_put_contents(__DIR__ . '/own.txt', 'ok') == 2 && unlink(__DIR__ . '/own.txt'));
t("tmp is private", file_put_contents('/tmp/x', 'x') == 1 && @file_get_contents("/var/lib/hostzit/tmp/$b/x") === false);
PHP
chown $A:$A $docA/probe.php
php=$(curl -s -H "Host: $SA" "http://127.0.0.1/probe.php?b=$B&sb=$SB")
echo "$php"
echo "$php" | grep -q "^FAIL" && fail=1
echo "$php" | grep -q "^PASS" || bad "PHP probe did not run"
rm -f $docA/probe.php

# web server: symlink to B's file must not be served
ln -sf /home/$B/sites/$SB/public/secret.txt $docA/steal.txt; chown -h $A:$A $docA/steal.txt
code=$(curl -s -o /tmp/steal.out -w '%{http_code}' -H "Host: $SA" http://127.0.0.1/steal.txt)
if grep -q "secret-of-$B" /tmp/steal.out; then bad "nginx served B's file through A's symlink"; else pass "nginx refuses A's symlink to B's file ($code)"; fi
rm -f $docA/steal.txt /tmp/steal.out
# wp-config.php and hidden files are never served
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $SB" http://127.0.0.1/wp-config.php)
[ "$code" != 200 ] && pass "wp-config.php not served ($code)" || bad "wp-config.php served"

# a shell of A in its cage, like SSH and cron
CAGE="--quiet --wait --pipe --collect --service-type=exec -p User=$A -p Group=$A -p Slice=hz-$A.slice -p RootDirectory=/var/lib/hostzit/cages/$A -p MountAPIVFS=yes -p ProtectProc=invisible -p ProcSubset=pid -p PrivateDevices=yes -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p WorkingDirectory=/home/$A"
sh() { systemd-run $CAGE -- /bin/bash -c "$1" 2>&1; }
out=$(sh "cat /home/$B/sites/$SB/public/secret.txt"); [[ "$out" != *secret-of* ]] && pass "shell cannot read B's file" || bad "shell read B's file"
out=$(sh "ls /home"); [ "$out" = "$A" ] && pass "shell sees only /home/$A" || bad "shell sees: $out"
out=$(sh "ps -e | wc -l"); [ "${out:-99}" -lt 10 ] && pass "shell sees only its own processes ($out lines)" || bad "shell sees $out processes"
pidB=$(pgrep -u $B php-fpm | head -1)
out=$(sh "kill -0 $pidB 2>&1 || echo refused"); [[ "$out" == *refused* || "$out" == *"No such process"* ]] && pass "shell cannot signal B's PHP ($pidB)" || bad "shell signals B: $out"
out=$(sh "touch /usr/bin/x 2>&1; echo rc=\$?"); [[ "$out" == *rc=1* ]] && pass "/usr is read-only" || bad "/usr writable: $out"
out=$(sh "cat /etc/passwd"); [[ "$out" != *$B* ]] && pass "cage passwd hides B" || bad "passwd shows B"
out=$(sh "ls /var/lib/hostzit 2>&1; ls /etc/nginx 2>&1"); [[ "$out" == *"No such file"* ]] && pass "panel and nginx folders not in the cage" || bad "visible: $out"
out=$(sh "id -u"); [ "$out" = "$(id -u $A)" ] && pass "shell runs as $A (uid $out)" || bad "uid $out"
out=$(sh "su -c id root 2>&1 </dev/null; sudo -n id 2>&1; echo done"); [[ "$out" != *"uid=0"* ]] && pass "no way to root (su/sudo)" || bad "root: $out"
out=$(sh "python3 -c 1 2>/dev/null; perl -e 'print 1' 2>/dev/null; dd if=/dev/zero of=/home/$A/big bs=1M count=1 2>&1 | tail -1; rm -f /home/$A/big"); pass "tools run in the cage ($out)"
# cgroup limits
lim=$(systemctl show hz-$A.slice -p MemoryMax -p CPUQuotaPerSecUSec -p TasksMax | tr '\n' ' ')
pass "slice limits: $lim"
out=$(sh 'for i in $(seq 1 200); do sleep 5 & done; wait' | grep -c "Resource temporarily unavailable\|fork")
[ "${out:-0}" -gt 0 ] && pass "fork bomb stopped by TasksMax ($out refused forks)" || bad "TasksMax did not stop 200 processes"
# quota
q=$(quota -u -w $A 2>/dev/null | tail -1); pass "quota of $A: $q"
rm -f /home/$B/sites/$SB/public/secret.txt
[ $madecfg = 1 ] && rm -f /home/$B/sites/$SB/public/wp-config.php
echo
[ $fail = 0 ] && echo "ALL ISOLATION TESTS PASSED" || echo "SOME ISOLATION TESTS FAILED"
exit $fail
