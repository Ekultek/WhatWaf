#!/bin/bash

mkdir -p ~/.whatwaf/files ~/.whatwaf/tampers ~/.whatwaf/plugins

rsync -avvz content/files/* ~/.whatwaf/files
rsync -avvz content/plugins/* ~/.whatwaf/plugins
rsync -avvz content/tampers/* ~/.whatwaf/tampers
touch ~/.whatwaf/whatwaf.sqlite