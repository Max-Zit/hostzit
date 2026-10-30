#!/bin/bash
# Builds a small but realistic cPanel full backup (cpmove-cpdemo.tar.gz) for
# import tests: a WordPress site copied from an existing HostZit site, its
# database, a database user with a native password hash, DNS zone, cron.
#   make-cpmove.sh SOURCE_DOCROOT SOURCE_DB
set -e
SRC=$1 SRCDB=$2 U=cpdemo D=cpdemo-shop.hostzit.test
W=/root/cpmove-build; rm -rf $W; mkdir -p $W/cpmove-$U/{homedir/public_html,homedir/mail,mysql,userdata,dnszones,cp,cron}
R=$W/cpmove-$U
cp -a $SRC/. $R/homedir/public_html/
mkdir -p $R/homedir/public_html/blog && echo '<?php echo "addon";' > $R/homedir/public_html/blog/index.php
echo "old mail" > $R/homedir/mail/README
PW='Cpanel-Db-Pass-123'
HASH=$(mariadb -N -e "SELECT CONCAT('*', UPPER(SHA1(UNHEX(SHA1('$PW')))))")
sed -i "s/define( 'DB_NAME', '[^']*' );/define( 'DB_NAME', '${U}_wp' );/; s/define( 'DB_USER', '[^']*' );/define( 'DB_USER', '${U}_wpuser' );/; s/define( 'DB_PASSWORD', '[^']*' );/define( 'DB_PASSWORD', '$PW' );/" $R/homedir/public_html/wp-config.php
mariadb-dump --single-transaction $SRCDB > $R/mysql/${U}_wp.sql
OLD=$(mariadb -N -e "SELECT option_value FROM $SRCDB.wp_options WHERE option_name='siteurl'")
sed -i "s#$OLD#http://$D#g" $R/mysql/${U}_wp.sql
cat > $R/mysql.sql <<SQL
GRANT USAGE ON *.* TO '$U'@'localhost' IDENTIFIED BY PASSWORD '*0000000000000000000000000000000000000000';
GRANT USAGE ON *.* TO '${U}_wpuser'@'localhost' IDENTIFIED BY PASSWORD '$HASH';
GRANT ALL PRIVILEGES ON \`${U}\_wp\`.* TO '${U}_wpuser'@'localhost';
SQL
cat > $R/userdata/main <<Y
---
addon_domains:
  cpdemo-blog.hostzit.test: blog.cpdemo-shop.hostzit.test
main_domain: $D
parked_domains:
  - cpdemo-alias.hostzit.test
sub_domains:
  - blog.cpdemo-shop.hostzit.test
Y
printf -- "---\ndocumentroot: /home/$U/public_html\nservername: $D\n" > $R/userdata/$D
printf -- "---\ndocumentroot: /home/$U/public_html/blog\n" > $R/userdata/blog.cpdemo-shop.hostzit.test
printf -- "---\ndocumentroot: /home/$U/public_html/blog\n" > $R/userdata/cpdemo-blog.hostzit.test
cat > $R/dnszones/$D.db <<Z
\$TTL 14400
$D. 86400 IN SOA ns1.oldhost.example. admin.oldhost.example. 2026010101 3600 1800 1209600 86400
$D. 86400 IN NS ns1.oldhost.example.
$D. IN A 203.0.113.50
www 14400 IN CNAME $D.
mail IN A 203.0.113.50
$D. IN MX 0 mail.$D.
$D. IN TXT "v=spf1 +a +mx ~all"
_dmarc IN TXT "v=DMARC1; p=none"
ftp IN A 203.0.113.50
legacy IN A 198.51.100.9
Z
printf "IP=203.0.113.50\nUSER=$U\nPLAN=default\nDNS=$D\n" > $R/cp/$U
printf "MAILTO=\"\"\n*/30 * * * * php -q /home/$U/public_html/wp-cron.php >/dev/null 2>&1\n" > $R/cron/$U
mkdir -p /var/lib/hostzit/import; chmod 700 /var/lib/hostzit/import
tar -czf /var/lib/hostzit/import/cpmove-$U.tar.gz -C $W cpmove-$U
ls -la /var/lib/hostzit/import/
