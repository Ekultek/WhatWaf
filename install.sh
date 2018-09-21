#!/bin/bash

chmod +x whatwaf.py
cp -R ./whatwaf /usr/local/etc/whatwaf
cat<<EOT >> /usr/local/bin/whatwaf
#!/bin/bash
# this is the execution script for whatWaf
# created by whatwaf install.sh on $(date +'%m-%d-%Y %H:%M:%S')
exec python /usr/local/etc/whatwaf/whatwaf.py $@
EOT
chmod +x /usr/local/bin/whatwaf
pip install -r requirements.txt