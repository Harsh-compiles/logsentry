# Deploying LogSentry on AWS

This builds the full lab: a monitor server running LogSentry, plus three servers (`web-01`, `web-02`, `bastion`) that forward their logs to it. Everything uses free-tier instance sizes. Setup takes about 10 minutes.

> **Cost:** 4 × t3.micro. The AWS free tier covers 750 instance-hours a month in total, so running all four non-stop uses it up in about a week. Run `terraform destroy` when you're not demoing, and set a [billing alarm](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/monitor_estimated_charges_with_cloudwatch.html) for peace of mind.

## 1. Prerequisites

- An AWS account and the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) configured (`aws configure`) with an IAM user, not the root account.
- [Terraform](https://developer.hashicorp.com/terraform/install) 1.5 or newer.
- An SSH key pair: `ssh-keygen -t ed25519` if you don't have one.
- This repository pushed to **your own public GitHub repo** (the servers `git clone` it during setup).

## 2. Configure

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
curl ifconfig.me        # your public IP
```

Edit `terraform.tfvars`:

```hcl
my_ip_cidr      = "142.134.10.20/32"   # your IP + /32
public_key_path = "~/.ssh/id_ed25519.pub"
repo_url        = "https://github.com/<your-username>/logsentry.git"
webhook_url     = "https://discord.com/api/webhooks/..."   # optional
```

To get a Discord webhook: in any server you own, *Server Settings → Integrations → Webhooks → New Webhook → Copy URL*.

## 3. Deploy

```bash
terraform init
terraform plan          # review what will be created
terraform apply
```

Outputs look like:

```
dashboard_url = "http://15.222.x.x:8080"
ssh_monitor   = "ssh ubuntu@15.222.x.x"
targets = {
  "bastion" = "3.98.x.x"
  "web-01"  = "15.156.x.x"
  "web-02"  = "35.183.x.x"
}
```

Wait about 3 minutes for the servers to install everything, then open `dashboard_url`.

## 4. Check it works

```bash
ssh ubuntu@<monitor-ip>
sudo tail -f /var/log/remote/remote.log      # logs arriving from all three hosts
sudo docker logs -f logsentry                # alerts printed as they fire
cat /var/log/logsentry-setup.log             # if something looks wrong
```

Then trigger an alert from your own machine (this one is harmless):

```bash
curl "http://<web-01-ip>/search?q=%27%20OR%201%3D1--"
```

A *SQL injection attempt* alert should appear on the dashboard within a second. For full attack scenarios, see [ATTACK_PLAYBOOK.md](ATTACK_PLAYBOOK.md).

## What gets created

| Resource | Purpose |
|---|---|
| VPC `10.0.0.0/16`, public subnet, internet gateway, route table | Isolated lab network |
| Security group `logsentry-monitor` | SSH + dashboard from your IP only; syslog TCP 514 from monitored hosts only |
| Security group `logsentry-targets` | SSH + HTTP from the internet (so real attacks arrive); all TCP from your attack machine (so scans reach the host firewall and get logged) |
| `monitor` (10.0.1.10) | rsyslog receiver + LogSentry container |
| `web-01`, `web-02` (nginx), `bastion` | Forward all logs; key-only SSH; UFW default-deny with scan logging |

Each monitored server's bootstrap script (`templates/target.sh.tftpl`):

1. Installs rsyslog and adds a forwarding rule to the monitor. The rule is named `10-…` so it runs before Ubuntu's `20-ufw.conf`, which ends with `stop` and would otherwise swallow the firewall logs.
2. Sends nginx's access log to syslog, so it is forwarded too.
3. Enforces key-only SSH, disables root login, sets `MaxAuthTries 3`.
4. Enables UFW and adds a logging rule for new connections to closed ports. UFW's built-in logging is rate-limited to about 3 lines a minute, which hides port scans.

## Tear down

```bash
terraform destroy
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard doesn't load | Your IP changed (home internet does this). Update `my_ip_cidr` and `terraform apply`. |
| `remote.log` is empty | On a target: `sudo systemctl status rsyslog` and check `/etc/rsyslog.d/10-logsentry-forward.conf` has the monitor IP. |
| No port-scan alerts | Scan from the IP in `my_ip_cidr` / `attacker_cidr`; other IPs are blocked by AWS before UFW sees them. |
| Container not running | `sudo docker logs logsentry` on the monitor; `cat /var/log/logsentry-setup.log`. |
