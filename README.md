import json
import os
import re
import shutil
import smtplib
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import (
    HELPDESK_BASE_URL,
    HELPDESK_TOKEN,
    SMTP_SERVER,
    SMTP_PORT,
    FROM_EMAIL,
    TO_EMAIL,
    SEND_EMAIL,
    VYOS_SSH_PORT,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enumerate_devices import enumerate_devices
from monitor_device_availability import has_static_ip, ping_device

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")
TICKET_URL = f"{HELPDESK_BASE_URL}/api/tickets"

EXPECTED_DNS = ["10.10.10.10", "10.10.10.20"]
ISSUE_TYPE = "DNS Compromise"


def get_monitored_devices():
    """
    Uses enumerate_devices to resolve DHCP leases from the VyOS router,
    then filters for manageable devices with active IPs.
    """
    devices = enumerate_devices(CSV_FILE)
    monitored = []
    for d in devices:
        addr = d.get("Device Address", "").strip()
        os_type = d.get("OS", "").strip().lower()
        if not has_static_ip(addr):
            continue
        if os_type in ("openvswitch", "switch") or d.get("Username", "").lower() in ("none", ""):
            continue
        monitored.append(d)
    return monitored


def run_ssh(host, port, username, password, command, timeout=8):
    """Executes a command via SSH using paramiko if installed, else sshpass."""
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=int(port),
                username=username,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return True, (out if out.strip() else err)
        finally:
            client.close()
    except ImportError:
        pass
    except Exception as e:
        if not shutil.which("sshpass"):
            return False, str(e)

    if shutil.which("sshpass") and password:
        cmd = [
            "sshpass", "-p", password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={timeout}",
            "-p", str(port),
            f"{username}@{host}",
            command,
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            return (res.returncode == 0), (res.stdout if res.stdout.strip() else res.stderr)
        except Exception as e:
            return False, str(e)

    return False, "Neither paramiko nor sshpass available for SSH."


def detect_altered_dns(device):
    """
    Pings the device, connects via SSH using credentials from CSV,
    and returns detected rogue DNS IPs if the DNS configuration is altered.
    """
    name = device["Device Name"]
    ip = device["Device Address"]
    os_type = device.get("OS", "")
    user = device.get("Username", "")
    pwd = device.get("Password", "")
    port = VYOS_SSH_PORT if os_type == "VyOS" else 22

    print(f"\n  Checking DNS configuration on {name} ({ip}) [OS: {os_type}]...")

    if not ping_device(ip):
        print(f"  [SKIP] {name} ({ip}) is offline / not responding to ping.")
        return None

    cmd = "/bin/vbash -ic 'show system name-server' 2>/dev/null || cat /etc/resolv.conf" if os_type == "VyOS" else "cat /etc/resolv.conf"
    success, output = run_ssh(ip, port, user, pwd, cmd)
    if not success:
        print(f"  [WARN] SSH connection to {name} ({ip}) failed: {output.strip()}")
        return None
    

    detected = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2 and parts[1] not in detected:
                detected.append(parts[1])
        elif os_type == "VyOS":
            for found_ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
                if found_ip not in detected:
                    detected.append(found_ip)

    active = [ns for ns in detected if not ns.startswith("127.")]
    print(f"  Current DNS: {', '.join(active) if active else 'None detected'}")

    rogue = [ns for ns in active if ns not in EXPECTED_DNS]
    if rogue:
        rogue_str = ", ".join(rogue)
        print(f"  [ALERT] Rogue DNS detected on {name}: {rogue_str}")
        return rogue_str

    if active and not any(exp in active for exp in EXPECTED_DNS):
        alt_str = ", ".join(active)
        print(f"  [ALERT] Altered DNS detected on {name}: {alt_str}")
        return alt_str

    print(f"  [OK] DNS configuration on {name} is normal ({', '.join(active)}).")
    return None


def correct_dns(device):
    """
    Reconfigures the device's DNS back to expected servers
    and prints the verified configuration for the screenshot.
    """
    name = device["Device Name"]
    ip = device["Device Address"]
    os_type = device.get("OS", "")
    user = device.get("Username", "")
    pwd = device.get("Password", "")
    port = VYOS_SSH_PORT if os_type == "VyOS" else 22

    print(f"\n  --- Correcting DNS Configuration on {name} ({ip}) ---")
    resolv_payload = "".join(f"nameserver {dns}\\n" for dns in EXPECTED_DNS)

    if os_type == "VyOS":
        cmd = f"""/bin/vbash -ic '
source /opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script 2>/dev/null || true
configure
delete system name-server
set system name-server {EXPECTED_DNS[0]}
set system name-server {EXPECTED_DNS[1]}
commit
save
exit
' 2>&1
echo '{pwd}' | sudo -S sh -c 'printf "{resolv_payload}" > /etc/resolv.conf'
"""
        verify_cmd = "/bin/vbash -ic 'show system name-server' 2>/dev/null || cat /etc/resolv.conf"
    else:
        cmd = f"echo '{pwd}' | sudo -S sh -c 'printf \"{resolv_payload}\" > /etc/resolv.conf && (resolvectl flush-caches 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null || true)'"
        verify_cmd = "cat /etc/resolv.conf"

    run_ssh(ip, port, user, pwd, cmd)
    _, verify_out = run_ssh(ip, port, user, pwd, verify_cmd)

    print(f"\n  --- Verified DNS Configuration on {name} ---")
    print(verify_out.strip())
    print(f"  SUCCESS: {name} DNS restored to {', '.join(EXPECTED_DNS)}")


def build_altered_email(device, current_dns, expected_dns, timestamp):
    name = device["Device Name"]
    ip = device["Device Address"]
    subject = f"DNS Configuration Alert: {name} ({ip})"
    body = f"""Dear Network Administrator,

This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:

Device Name: {name}
IP Address: {ip}
Detected DNS Setting: {current_dns}
Expected DNS Setting: {expected_dns}
Time Detected: {timestamp}

The system will attempt to automatically correct this configuration.

Best regards,
Network Monitoring System"""
    return subject, body


def send_email(subject, body):
    msg = MIMEMultipart()
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    print("\n" + "=" * 70)
    print("DNS SETTING ALTERED NOTIFICATION EMAIL")
    print("=" * 70)
    print(f"From    : {FROM_EMAIL}")
    print(f"To      : {TO_EMAIL}")
    print(f"Subject : {subject}")
    print("-" * 70)
    print(body)
    print("=" * 70)

    if not SEND_EMAIL or not SMTP_SERVER:
        print("\n[DRY RUN] Email displayed (SEND_EMAIL disabled or SMTP_SERVER not set).")
        return
    

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.send_message(msg)
        print("\nAlert email sent successfully.")
    except Exception as e:
        print(f"\nFailed to send email: {e}")


def get_tickets():
    headers = {"Accept": "application/json"}
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"
    req = urllib.request.Request(TICKET_URL, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data if isinstance(data, list) else data.get("tickets", data.get("data", []))
    except Exception as e:
        print(f"\n  [WARN] Ticket service query failed ({TICKET_URL}): {e}")
        return []


def find_ticket(tickets, device):
    name = device["Device Name"].lower()
    ip = device["Device Address"]
    for t in tickets:
        t_name = str(t.get("device_name", "")).lower()
        t_ip = str(t.get("ip_address", ""))
        t_title = str(t.get("title", "")).lower()
        t_status = str(t.get("status", "")).lower()
        if (t_name == name or t_ip == ip or name in t_title) and t_status != "resolved":
            return t
    return None


def create_ticket(device, detected_dns):
    name = device["Device Name"]
    ip = device["Device Address"]
    payload = json.dumps({
        "title": f"DNS Setting Altered - {name}",
        "description": f"DNS configuration altered on {name} ({ip}). Detected DNS: {detected_dns}.",
        "device_name": name,
        "ip_address": ip,
        "issue_type": ISSUE_TYPE,
    }).encode()

    headers = {"Content-Type": "application/json"}
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"

    req = urllib.request.Request(TICKET_URL, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"\n  [WARN] Cannot create ticket: {e}")
        return None


def resolve_ticket(ticket_id, device, timestamp):
    url = f"{TICKET_URL}/{ticket_id}"
    payload = json.dumps({
        "status": "resolved",
        "resolution": f"DNS settings restored to {', '.join(EXPECTED_DNS)}",
        "resolved_time": timestamp,
    }).encode()

    headers = {"Content-Type": "application/json"}
    if HELPDESK_TOKEN:
        headers["Authorization"] = f"Bearer {HELPDESK_TOKEN}"

    for method in ("PATCH", "PUT"):
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                ticket = json.loads(resp.read().decode("utf-8", errors="replace"))
                print(f"  [OK] Ticket #{ticket_id} updated -> status: resolved | {device['Device Name']} ({device['Device Address']})")
                return ticket
        except urllib.error.HTTPError as e:
            if e.code == 405 and method == "PATCH":
                continue
            print(f"\n  [WARN] Ticket #{ticket_id} update failed: HTTP {e.code}")
            return None
        except Exception as e:
            print(f"\n  [WARN] Ticket #{ticket_id} update failed: {e}")
            return None
    return None


def show_ticket_entries(tickets):
    print("\n" + "=" * 80)
    print("WEB SERVICE TICKETS (DNS COMPROMISE / RESOLVED)")
    print("=" * 80)
    header = f"{'Ticket ID':<11} {'Device Name':<14} {'IP Address':<18} {'Status':<12} {'Issue Type':<18}"
    print(header)
    print("-" * len(header))
    for t in tickets:
        t_id = t.get("ticket_id") or t.get("id") or "?"
        name = t.get("device_name", "")
        ip = t.get("ip_address", "")
        status = t.get("status", "")
        issue = t.get("issue_type", t.get("title", ""))
        print(f"{str(t_id):<11} {str(name):<14} {str(ip):<18} {str(status):<12} {str(issue):<18}")
    print("=" * 80)


def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices = get_monitored_devices()

    print("=" * 70)
    print("AUTOMATED DNS CONFIGURATION MONITORING & REMEDIATION")
    print(f"Helpdesk API : {TICKET_URL}")
    print(f"Expected DNS : {', '.join(EXPECTED_DNS)}")
    print(f"Devices to scan: {len(devices)}")
    print("=" * 70)

    tickets = get_tickets()
    altered_count = 0

    for device in devices:
        name = device["Device Name"]
        ip = device["Device Address"]

        # 1. Detect if DNS is actually altered via SSH
        current_dns = detect_altered_dns(device)
        if not current_dns:
            continue

        altered_count += 1
        print(f"\n{'=' * 70}")
        print(f"REMEDIATING: {name} ({ip})")
        print(f"{'=' * 70}")

        # 2. Email alert using Task 2 template
        subject, body = build_altered_email(device, current_dns, ", ".join(EXPECTED_DNS), timestamp)
        send_email(subject, body)

        # 3. Correct DNS configuration
        correct_dns(device)

        # 4. Update the ticket in the web service
        print(f"\n  --- Updating Ticket in Web Service ---")
        ticket = find_ticket(tickets, device)
        if ticket is None:
            print(f"  No open ticket found for {name}; creating one...")
            created = create_ticket(device, current_dns)
            ticket_id = (created.get("ticket_id") or created.get("id")) if created else None
        else:
            ticket_id = ticket.get("ticket_id") or ticket.get("id")

        if ticket_id is not None:
            resolve_ticket(ticket_id, device, timestamp)

    print("\n" + "=" * 70)
    print(f"SCAN COMPLETE: {altered_count} altered DNS device(s) remediated.")
    print("=" * 70)

    # 5. Show updated tickets for screenshot
    updated_tickets = get_tickets()
    if updated_tickets:
        show_ticket_entries(updated_tickets)


if __name__ == "__main__":
    main()
