#!/bin/bash

# We remount /dev/shm to prevent docker from mounting it with noexec,
# which stops the shared_memory PoC from working. While docker does
# mount /dev/shm noexec by default, major distributions (Ubuntu, Debian)
# do not.

docker run --rm -it  \
    -v /dev/shm --tmpfs /dev/shm:rw,nosuid,nodev,exec,size=4g  \
    pku:latest \
    /bin/bash -c 'cd /root/pku-exploits ; make test'



