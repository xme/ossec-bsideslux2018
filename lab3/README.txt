 _          _    _____           ____
| |    __ _| |__|___ /          |  _ \ _ __ ___   ___ ___  ___ ___  ___  ___
| |   / _` | '_ \ |_ \   _____  | |_) | '__/ _ \ / __/ _ \/ __/ __|/ _ \/ __|
| |__| (_| | |_) |__) | |_____| |  __/| | | (_) | (_|  __/\__ \__ \  __/\__ \
|_____\__,_|_.__/____/          |_|   |_|  \___/ \___\___||___/___/\___||___/

Introduction
------------
The purpose of this lab is to track malicious processes that are runninng on a
host. About malicious processes, we speak about bots, cryptominers, trojans, ...

Recipe
------
We will use the special <command> </command> feature to monitor the output of a
specific command. The idea is to grep a list of running processes on the monitored host and to compare it with a list of malicious or suspicous processes.

Steps
-----

1. Create a new local file entry based on command line

# cd /var/ossec/etc
# vi ossec.conf

Add the following block at the end of the file:

<localfile>
 <log_format>full_command</log_format>
 <command>find /proc -name comm -exec cat "{}" \; 2>/dev/null|sort -u</command>
 <frequency>180</frequency>
</localfile>

Save the file and exit

2. Create a new rule to detect suspicious process names

# cd /var/ossec/rules
# vi local_rules.xml

Add a new rule at the bottom of the file:

<rule id="100405" level="7" ignore="7200">
  <if_sid>530</if_sid>
  <match>ossec: output: 'find /proc</match>
  <regex>minerd|minergate|minexmr|mixnerdx|myatd|polkitd|rootv2.sh</regex>
  <description>Searching for suspicious processes</description>
  <group>hunting,</group>
</rule>

Note: it must be IN the Syslog <group> block!

Save the file and restart OSSEC

3. Test your new rule

Launch the pseudo test script in the lab3/ directory

# cd /home/student/lab3
# ./minerd &

Note: don't forget the '&' to detach it from the terminal

Now, wait for the alert to pop up in a few seconds:

# cd /var/ossec/logs/alerts
# tail -f alerts.log

Congratulations, you spotted the bad process!
