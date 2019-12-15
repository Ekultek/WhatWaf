# Features
 - Ability to run on a single URL with the `-u/--url` flag
 - Ability to run through a list of URL's with the `-l/--list` flag
 - Ability to detect over 70+ different firewalls
 - Ability to try over 30+ different tampering techniques
 - Ability to pass your own payloads either from a file, from the terminal, or use the default payloads
 - Default payloads that _should_ produce at least one WAF triggering
 - Ability to bypass firewalls using both SQLi techniques and cross site scripting techniques
 - Ability to run behind any proxy type that matches this regex:`(socks\d+)?(http(s)?)?://` (socks5, socks4, http, https)
 - Ability to use a random user agent, personal user agent, or custom default user agent
 - Auto assign protocol to HTTP or ability to force protocol to HTTPS
 - A built in encoder so you can encode your payloads into the discovered bypasses
 - Automatic issue creation if an unknown firewall is discovered
 - Ability to send output to a JSON, CSV, or YAML file
 - Ability to encode provided payloads using builtin tamper scripts
 - Encoded payloads are then saved into a database file for future use
 - Ability to export cached payloads from the database to a YAML, JSON, CSV, or textual file
 - Ability to save all traffic into files for further analysis by passing the `--traffic` flag
 - Ability to try and determine the backend webserver hosting the web application using `-W`
 - Ability to send POST or GET requests
 - Ability to pass in your own custom headers
 - More to come...

# Installation

Installing whatwaf is super easy, whatwaf is compatible with Python2 and Python3, all you have to do is the following:

```bash
./setup.sh install
```

This will install whatwaf into `~/.whatwaf/.install/bin` which will allow you to run it from the terminal just by using `whatwaf`

You can also install it manually by running the following:
```
sudo -s << EOF
git clone https://github.com/ekultek/whatwaf.git
cd whatwaf
chmod +x whatwaf.py
pip install -r requirements.txt
./whatwaf.py --help
EOF
```

Or you can run whatwaf in a virtual environment by doing the following (requires `virtualenv` to be installed):
```bash
sudo -s << EOF
pip install virtualenv
git clone https://github.com/ekultek/whatwaf.git
cd whatwaf
chmod +x whatwaf.py
virtualenv venv && source venv/bin/activate
pip install -r requirements.txt
./whatwaf.py --help
EOF
```

You can also install whatwaf using Docker with the following:
```
git clone https://github.com/ekultek/whatwaf
cd whatwaf
sudo docker build -t whatwaf .
sudo docker run -it whatwaf whatwaf --help
```

# Proof of concept

First we'll run the website through WhatWaf and figure out which firewall protects it (if any):
![item1](http://i67.tinypic.com/142y9s6.png)

Next we'll go to that website and see what the page looks like:
![item2](http://i64.tinypic.com/262mjhl.png)

Hmm.. that doesn't really look like Cloudflare does it? Lets see what the headers say:
![item4](http://i66.tinypic.com/5txx5x.png)

And finally, lets try one of the bypasses that it tells us to try:
![item3](http://i66.tinypic.com/sdi3x0.png)

# Demo video

[![to_video](http://i67.tinypic.com/2daawow.png)](https://vimeo.com/247623511)

# Get involved!

If you want to make some tamper scripts, want to add some functionality or just want to make something look better. Getting involved is easy:

 1. Fork the repository
 2. Edit the code to your liking
 3. Send a pull request

I'm always looking for some helpful people out there, and would love help with this little side project I got going on, Thanks! 
