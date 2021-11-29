# cpanel-patches
cpanel-patches

AutoSSL patch for Enabled.pm, run the following commands to fix it:

cp -vp /usr/local/cpanel/Cpanel/Services/Enabled.pm /root/Enabled.pm.backup
wget -O /usr/local/cpanel/Cpanel/Services/Enabled.pm https://raw.githubusercontent.com/gdajer/cpanel-patches/main/Enabled.pm
mv /var/cpanel/hostname_cert_csrs{,.cpbkp} -v
/usr/local/cpanel/bin/checkallsslcerts --verbose
