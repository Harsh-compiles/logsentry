variable "region" {
  description = "AWS region (ca-central-1 = Montreal)"
  type        = string
  default     = "ca-central-1"
}

variable "my_ip_cidr" {
  description = "Your public IP as a /32, e.g. 142.134.10.20/32 (find it with: curl ifconfig.me). Only this IP can open the dashboard."
  type        = string

  validation {
    condition     = can(cidrhost(var.my_ip_cidr, 0)) && var.my_ip_cidr != "0.0.0.0/0"
    error_message = "Use your own IP as a /32, never 0.0.0.0/0 - the dashboard must not be public."
  }
}

variable "attacker_cidr" {
  description = "IP of the machine you run nmap/hydra from. Defaults to my_ip_cidr."
  type        = string
  default     = ""
}

variable "public_key_path" {
  description = "SSH public key used to log in to the instances"
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "instance_type" {
  description = "EC2 instance type (t3.micro is free-tier eligible in most regions)"
  type        = string
  default     = "t3.micro"
}

variable "repo_url" {
  description = "Public Git URL of this repository (the servers clone it to install LogSentry)"
  type        = string
  default     = "https://github.com/Harsh-compiles/logsentry.git"
}

variable "webhook_url" {
  description = "Optional Discord or Slack webhook for alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "alert_level" {
  description = "Minimum severity sent to the webhook: low, medium, high or critical"
  type        = string
  default     = "high"
}

variable "api_token" {
  description = "Optional token required to change alert status through the API"
  type        = string
  default     = ""
  sensitive   = true
}
