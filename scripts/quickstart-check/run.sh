#!/bin/sh
# Inside a container of the image check.sh builds (the quickstart's Linux prerequisites:
# Dockerfile), user.sh as a new user with umask $1, installing with $2 (uv or pipx), with its
# own private group or, with $3 = shared, the shared group `users` as its primary group, and the scenario $4
# (check.sh lists them; plain when not given). The attack scenario adds a second account, bob,
# in the same group. Made-up data only.
set -e
if [ "$4" = linked-home ]; then
  # /home is a link, as on Fedora Silverblue (/home -> var/home): the home folder is still home
  mkdir -p /var/home && rmdir /home 2>/dev/null; rm -rf /home && ln -s var/home /home
fi
if [ "$3" = shared ]; then useradd -m -g users tester; else useradd -m tester; fi
if [ "$4" = outside-python ]; then
  # a folder outside the home folder that the user owns, for a Python of their own (a lab's)
  mkdir /opt/py && chown tester: /opt/py
fi
if [ "$4" = attack ]; then
  useradd -m -g users bob
  echo "tester ALL=(bob) NOPASSWD: ALL" > /etc/sudoers.d/bob
fi
su - tester -c "umask $1; INSTALLER=$2 SCENARIO=${4:-plain} sh /qs/user.sh"
