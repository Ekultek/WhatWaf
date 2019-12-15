#!/bin/bash

########
#
# script that will be ran by docker
#
########

apt-get update && apt-get install -y python python-pip git rsync
if [[ ! -d /tmp/ww ]]; then
  mkdir -p /tmp/ww
fi;
cd /tmp/ww && git clone https://github.com/ekultek/whatwaf && cd whatwaf
pip install pyyaml pysocks
pip install -r requirements.txt
echo "root" | python setup.py install