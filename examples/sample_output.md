# Sample Output

Real output from running the toolkit locally.

## Generating the sample log

```
$ python3 src/log_generator.py
Generated 95 log lines -> data/sample_auth.log
  Normal logins: 14
  Brute-force attack lines: 81 (from 185.220.101.47)
```

A snippet of the generated log (`data/sample_auth.log`):

```
Aug 23 06:29:00 web-prod-01 sshd[2679]: Accepted password for papi from 102.68.79.201 port 48024 ssh2
Aug 23 07:53:00 web-prod-01 sshd[4582]: Accepted password for papi from 196.207.32.11 port 41041 ssh2
Aug 23 08:37:00 web-prod-01 sshd[9928]: Accepted password for admin from 41.90.12.34 port 58390 ssh2
Aug 23 09:12:03 web-prod-01 sshd[3340]: Invalid user admin from 185.220.101.47
Aug 23 09:12:03 web-prod-01 sshd[5339]: Failed password for invalid user admin from 185.220.101.47 port 55035 ssh2
Aug 23 09:12:04 web-prod-01 sshd[9830]: Invalid user ubuntu from 185.220.101.47
Aug 23 09:12:04 web-prod-01 sshd[5304]: Failed password for invalid user ubuntu from 185.220.101.47 port 58394 ssh2
...
```

## Running the detector

```
$ python3 src/detector.py data/sample_auth.log

=================================================================
 Intrusion Detection Report
=================================================================
 Total events parsed:      95
   Failed logins:          42
   Accepted logins:        13
   Invalid-user attempts:  40
-----------------------------------------------------------------
 [ALERT] Brute-force activity detected from 1 IP(s):

  IP: 185.220.101.47
    Attempts:        30 failed logins in 60.0s
    Window:          2026-08-23 09:12:07 -> 2026-08-23 09:13:07
    Usernames tried: admin, administrator, backup, demo, ftpuser, git, guest, info ...

-----------------------------------------------------------------
 [CRITICAL] 1 likely compromise(s) detected:

  IP 185.220.101.47 logged in as 'admin' at 2026-08-23 09:13:27
    -> 20.0s after its brute-force burst ended.
    Recommended action: disable/rotate this account's credentials, review its recent activity, and block the source IP.

=================================================================
```

**Key takeaway for a portfolio/README:** the detector didn't just
count failed logins — it correctly identified the 60-second window
where 30 failed attempts happened, listed which usernames were tried,
and then connected that burst to the successful login that followed
20 seconds later. That correlation (burst → success) is the signal a
real analyst would treat as a confirmed breach, not just noise.
