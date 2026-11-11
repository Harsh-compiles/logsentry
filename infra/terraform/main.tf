# LogSentry lab on AWS:
#   * 1 monitor  (rsyslog receiver + LogSentry dashboard)
#   * 2 web servers + 1 bastion that forward all their logs to the monitor
# Everything fits in the AWS free tier (t3.micro / t2.micro).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "logsentry"
      ManagedBy = "terraform"
    }
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ---------------------------------------------------------------- network
resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "logsentry-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "logsentry-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "logsentry-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = "logsentry-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------- firewalls
resource "aws_security_group" "monitor" {
  name        = "logsentry-monitor"
  description = "LogSentry monitor: dashboard and SSH from your IP only, syslog from monitored hosts"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from your IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }

  ingress {
    description = "Dashboard from your IP"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }

  ingress {
    description     = "Syslog (TCP) from monitored hosts"
    from_port       = 514
    to_port         = 514
    protocol        = "tcp"
    security_groups = [aws_security_group.targets.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "targets" {
  name        = "logsentry-targets"
  description = "Monitored hosts: SSH and HTTP open to the internet so real attack traffic shows up"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH (key-only auth) - internet bots will try to brute force this"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Let *your* attack machine reach every port, so the host firewall (UFW)
  # sees and logs your nmap scans instead of AWS silently dropping them.
  ingress {
    description = "All TCP from the attacker machine (you)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.attacker_cidr != "" ? var.attacker_cidr : var.my_ip_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------- instances
resource "aws_key_pair" "lab" {
  key_name   = "logsentry-key"
  public_key = file(pathexpand(var.public_key_path))
}

locals {
  monitor_ip = "10.0.1.10"
  targets = {
    "web-01"  = { ip = "10.0.1.11", web = true }
    "web-02"  = { ip = "10.0.1.12", web = true }
    "bastion" = { ip = "10.0.1.13", web = false }
  }
}

resource "aws_instance" "monitor" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  private_ip             = local.monitor_ip
  key_name               = aws_key_pair.lab.key_name
  vpc_security_group_ids = [aws_security_group.monitor.id]

  user_data = templatefile("${path.module}/templates/monitor.sh.tftpl", {
    repo_url    = var.repo_url
    webhook_url = var.webhook_url
    alert_level = var.alert_level
    api_token   = var.api_token
  })
  user_data_replace_on_change = true

  root_block_device {
    volume_size = 16
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }

  tags = { Name = "logsentry-monitor", Role = "monitor" }
}

resource "aws_instance" "target" {
  for_each = local.targets

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  private_ip             = each.value.ip
  key_name               = aws_key_pair.lab.key_name
  vpc_security_group_ids = [aws_security_group.targets.id]

  user_data = templatefile("${path.module}/templates/target.sh.tftpl", {
    hostname   = each.key
    monitor_ip = local.monitor_ip
    repo_url   = var.repo_url
    web        = each.value.web
  })
  user_data_replace_on_change = true

  root_block_device {
    volume_size = 8
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = { Name = "logsentry-${each.key}", Role = "target" }

  depends_on = [aws_instance.monitor]
}
