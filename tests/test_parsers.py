from datetime import datetime, timezone

from logsentry.parsers import parse_line

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def test_ssh_failed_invalid_user():
    ev = parse_line("Nov 11 10:15:02 web-01 sshd[1234]: Failed password for invalid user admin "
                    "from 203.0.113.5 port 52314 ssh2", now=NOW)
    assert ev.kind == "ssh_failed"
    assert ev.src_ip == "203.0.113.5"
    assert ev.user == "admin"
    assert ev.fields["invalid_user"] is True
    assert ev.host == "web-01"
    assert ev.ts == datetime(2026, 11, 11, 10, 15, 2, tzinfo=timezone.utc)


def test_ssh_accepted_iso_timestamp():
    ev = parse_line("2026-11-11T10:15:02.123456+00:00 bastion sshd[99]: Accepted publickey for ubuntu "
                    "from 10.0.1.25 port 50000 ssh2")
    assert ev.kind == "ssh_accepted"
    assert ev.user == "ubuntu"
    assert ev.fields["method"] == "publickey"
    assert ev.ts.microsecond == 123456


def test_syslog_year_rollover():
    # A December line read in early January belongs to the previous year.
    ev = parse_line("Dec 31 23:59:59 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
                    now=datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc))
    assert ev.ts.year == 2026


def test_ssh_preauth_disconnect_counts_as_failure():
    # What internet bots produce against a key-only server.
    ev = parse_line("Nov 11 10:15:02 web-01 sshd[1]: Connection closed by invalid user oracle 192.0.2.44 port 4444 "
                    "[preauth]", now=NOW)
    assert ev.kind == "ssh_failed" and ev.user == "oracle" and ev.fields["invalid_user"] is True
    ev = parse_line("Nov 11 10:15:02 web-01 sshd[1]: Disconnected from authenticating user root 192.0.2.44 port 1 "
                    "[preauth]", now=NOW)
    assert ev is None  # "Disconnected from" follows another line for the same attempt; don't double count
    ev = parse_line("Nov 11 10:15:02 web-01 sshd[1]: Connection closed by authenticating user root 192.0.2.44 port 1 "
                    "[preauth]", now=NOW)
    assert ev.kind == "ssh_failed" and ev.user == "root"


def test_sudo_command_and_denied():
    ok = parse_line("Nov 11 10:00:00 web-01 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; "
                    "COMMAND=/usr/bin/apt update", now=NOW)
    assert ok.kind == "sudo_cmd" and ok.user == "ubuntu" and ok.fields["command"] == "/usr/bin/apt update"
    denied = parse_line("Nov 11 10:00:00 web-01 sudo:   intern : user NOT in sudoers ; TTY=pts/1 ; "
                        "PWD=/home/intern ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", now=NOW)
    assert denied.kind == "sudo_denied" and denied.user == "intern"


def test_ufw_block():
    ev = parse_line("Nov 11 10:00:00 web-01 kernel: [1234.5] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=198.51.100.9 "
                    "DST=10.0.1.10 LEN=44 PROTO=TCP SPT=40000 DPT=3389 WINDOW=1024 SYN URGP=0", now=NOW)
    assert ev.kind == "fw_block"
    assert ev.src_ip == "198.51.100.9"
    assert ev.fields["dst_port"] == 3389


def test_plain_nginx_line_decodes_payload():
    ev = parse_line('203.0.113.7 - - [11/Nov/2026:10:15:02 +0000] "GET /p?id=1%2527%20OR%201%3D1 HTTP/1.1" '
                    '200 512 "-" "sqlmap/1.8"', default_host="web-02")
    assert ev.kind == "http_request"
    assert ev.host == "web-02"
    assert ev.fields["status"] == 200
    assert "' OR 1=1" in ev.fields["decoded_path"]  # double URL-encoding is undone
    assert ev.fields["user_agent"] == "sqlmap/1.8"


def test_nginx_forwarded_through_syslog():
    ev = parse_line('2026-11-11T10:15:02.5+00:00 web-01 nginx: 203.0.113.7 - - [11/Nov/2026:10:15:02 +0000] '
                    '"GET / HTTP/1.1" 200 10 "-" "curl/8"')
    assert ev.host == "web-01" and ev.src_ip == "203.0.113.7"
    assert ev.ts.microsecond == 500000


def test_irrelevant_lines_are_ignored():
    assert parse_line("") is None
    assert parse_line("Nov 11 10:00:00 web-01 systemd[1]: Started Daily apt upgrade.", now=NOW) is None
    assert parse_line("Nov 11 10:00:00 web-01 sshd[1]: pam_unix(sshd:session): session opened", now=NOW) is None
    assert parse_line("this is not a log line") is None
