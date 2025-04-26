
#SMTP user enumeration tool.

Enumerates the SMTP service and finds the usernames that exists on the system.

pip install pwn

```shell
./smtp-user-recon.py
Usage: ./smtp-vrfy.py <SMTP Server> <Path to Wordlist
```


example for HTB box:

```shell
./smtp-user-recon.py 10.129.134.202 ~/Downloads/Footprinting-wordlist/footprinting-wordlist.txt
[*] Starting SMTP VRFY scan on 10.129.134.202
[*] Using wordlist: /home/olddog/Downloads/Footprinting-wordlist/footprinting-wordlist.txt
[+] Opening connection to 10.129.134.202 on port 25: Done
[*] Server banner: 220 InFreight ESMTP v2.11
[*] Sending HELO command...
[*] HELO response: 250 mail1
[*] Testing 101 usernames...
...
[!] Server limiting connections: 421 4.7.0 mail1 Error: too many errors
[*] Reconnecting and continuing with username: joshua
[*] Closed connection to 10.129.134.202 port 25
[+] Opening connection to 10.129.134.202 on port 25: Done
[*] Server banner: 220 InFreight ESMTP v2.11
[*] Sending HELO command...
[*] HELO response: 250 mail1
[-] Invalid User: joshua
...
[*] Closed connection to 10.129.134.202 port 25

[+] Found 1 valid users:
    - rxxn
```


