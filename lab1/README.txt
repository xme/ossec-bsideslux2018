 _          _     _           ____  _   _ ____
| |    __ _| |__ / |         |  _ \| \ | / ___|
| |   / _` | '_ \| |  _____  | | | |  \| \___ \
| |__| (_| | |_) | | |_____| | |_| | |\  |___) |
|_____\__,_|_.__/|_|         |____/|_| \_|____/

Introduction
------------
DNS is a gold mine for security analysts!

The purpose of this lab is to track hosts trying to communicate with suspicious
hosts on the Internet. It can be a host trying to download some payload from a
compromized host or an already infected host trying to contact its C2 server.

By watching DNS logs, we can easily spot potentially infected or targeted hosts.

Recipe
------
To detect suspicious traffic, let's keep an eye on the DNS resolver log file.
To achieve this, one of the best sources to hunt is the DNS resolver log file.

OSSEC has a 'list' feature that can be used to query any fields from rules
against lists. In this case, we will generate a list of malicious domain names
and correlate it with the queried domains.

Where to find suspicious domain names? They're nice lists available for free on
the Internet!

Steps
-----

1. Your instance is running a local resolver (bind9). All queries are logged in
/var/log/named/queries.log. First, test the server:

- Check resolv.conf
- Try to resolve a domain name

# host www.google.com

- Check that logs are working properly

# grep google /var/log/named/queries.log

2. Let's configure OSSEC to process the log file

# cd /var/ossec/etc

# vi ossec.conf

Navigate to the EOF and below the other log file description, add:

<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/named/queries.log</location>
</localfile>

Save the file, and restart OSSEC

# systemctl restart ossec

3. The problem is that the latest bind log format channged and OSSEC does not recognize it. We need to adapt the decoder

# cd /var/ossec/etc

# vi local_decoder.xml

Add this:

<decoder name="bind9">
    <prematch>info: client @0x</prematch>
    <regex offset="after_prematch">\S+\s(\d+.\d+.\d+.\d+)#\d+\s\((\S+)\)</regex>
    <order>srcip,url</order>
</decoder>

Save the file and restart OSSEC

Test the new decoder:

# tail -f /var/log/named/queries.log

(copy the last line)

# /var/ossec/bin/ossec-logtest

(paste the line)

4. Generate the list of "bad" domains

Create a new list for OSSEC

# cd /var/ossec/etc

# vi ossec.conf

Search for <include>local_rules.xml</include> entries and add a new line below:

<list>lists/baddomains.cdb</list>

Save the file and restart OSSEC

Create the directory /var/ossec/lists

A script is ready in /var/ossec/bin/update_list_baddomains.sh

# /var/ossec/bin/update_list_baddomains.sh

(This script should be executed from a cron once a day)

5. Create a new rule to match bad domains that are resolved

# cd /var/ossec/rules

# vi local_rules.xml

Add the following rule:

<rule id="99002" level="10">
    <decoded_as>bind9</decoded_as>
    <list field="url">lists/baddomains</list>
    <description>DNS query for malicious domain! (lists/justdomains)</description>
</rule>

Save the file and restart OSSEC

6. Let's test!

Try to resolve a malicious domainn:

# dig zdbd12.co.vu

Verify the bind logs:

# grep zdbd12.co.vu /var/log/named/queries.log

Verify the OSSEC alerts:

# grep zdbd12.co.vu /var/ossec/logs/alerts/alerts.log

You can also copy/paste the query log to ossec-logtest:

# /var/ossec/bin/ossec-logtest

Congratulations, you can now spot maicious domains!
