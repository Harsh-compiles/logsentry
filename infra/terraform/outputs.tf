output "dashboard_url" {
  description = "LogSentry dashboard (reachable from your IP only). Allow ~3 minutes for setup after apply."
  value       = "http://${aws_instance.monitor.public_ip}:8080"
}

output "ssh_monitor" {
  value = "ssh ubuntu@${aws_instance.monitor.public_ip}"
}

output "targets" {
  description = "Public IPs of the monitored machines - point your attacks here"
  value       = { for name, inst in aws_instance.target : name => inst.public_ip }
}

output "web_urls" {
  value = [for name, inst in aws_instance.target : "http://${inst.public_ip}" if local.targets[name].web]
}
