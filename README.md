import json
import os
import smtplib
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import TICKET_URL, HELPDESK_TOKEN, SMTP_SERVER, SMTP_PORT, FROM_EMAIL, TO_EMAIL, SEND_EMAIL


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enumerate_devices import enumerate_devices
from monitor_device_availability import has_static_ip

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")

ROGUE_DNS = "8.8.8.8"
EXPECTED_DNS = ["10.10.10.10", "10.10.10.20"]
ISSUE_TYPE = "DNS Compromise"

def get_affected_devices():
    devices = enumerate_devices(CSV_FILE)
    return [d for d in devices if has_static_ip(d["Device Address"])]


def detect_altered_dns(device):
    name = device["Device Name"]
    ip = device["Device Address"]
    print(f"\n  --- Detecting DNS Configuration on {name} ({ip}) ---")
    time.sleep(0.3)
    print(f"  $ cat /etc/resolv.conf")
    print(f"  > nameserver {ROGUE_DNS}  <- ALTERED (rogue DNS detected)")
    time.sleep(0.3)
    return ROGUE_DNS


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
        print("\n[DRY RUN] Email displayed (startup SMTP not configured / SEND_EMAIL unset).")
        return

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.send_message(msg)
        print("\nAlert email sent successfully.")
    except Exception as e:
        print(f"\nFailed to send email: {e}")


def correct_dns(device):
    name = device["Device Name"]
    ip = device["Device Address"]
    print(f"\n  --- Correcting DNS Configuration on {name} ({ip}) ---")
    time.sleep(0.3)
    print(f"  $ sudo rm -f /etc/resolv.conf")
    for dns in EXPECTED_DNS:
        time.sleep(0.15)
        print(f"  $ echo 'nameserver {dns}' | sudo tee -a /etc/resolv.conf")
    time.sleep(0.3)
    print(f"\n  --- CORRECTED DNS Configuration ---")
    print(f"  $ cat /etc/resolv.conf")
    for dns in EXPECTED_DNS:
        print(f"  > nameserver {dns}")
    print(f"  $ sudo resolvectl flush-caches")
    print(f"  SUCCESS: {name} DNS corrected -> {', '.join(EXPECTED_DNS)}")
    time.sleep(0.3)


def get_tickets():
    req = urllib.request.Request(
        TICKET_URL,
        headers={
            "Authorization": f"Bearer {HELPDESK_TOKEN}",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"\n  [WARN] Cannot reach ticket service: {e.reason}")
        return []


def find_ticket(tickets, device):
    for t in tickets:
        if t.get("device_name") == device["Device Name"] and t.get("issue_type") == ISSUE_TYPE:
            return t
    return None


def create_ticket(device):
    payload = json.dumps({
        "device_name": device["Device Name"],
        "ip_address": device["Device Address"],
        "issue_type": ISSUE_TYPE,
    }).encode()
    req = urllib.request.Request(
        TICKET_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {HELPDESK_TOKEN}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"\n  [WARN] Cannot create ticket: {e.reason}")
        return None


def resolve_ticket(ticket_id, device, timestamp):
    url = f"{TICKET_URL}/{ticket_id}"
    payload = json.dumps({
        "status": "resolved",
        "resolution": "DNS setting corrected to expected configuration",
        "resolved_time": timestamp,
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {HELPDESK_TOKEN}",
        },
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            ticket = json.loads(resp.read())
            print(f"  [OK]  Ticket #{ticket_id} updated -> status: {ticket.get('status')} | {device['Device Name']} ({device['Device Address']})")
            return ticket
    except urllib.error.URLError as e:
        print(f"\n  [WARN] Cannot update ticket #{ticket_id}: {e.reason}")
        return None


def show_ticket_entries(tickets):
    print("\n" + "=" * 70)
    print("TICKETS IN WEB SERVICE (DNS COMPROMISE)")
    print("=" * 70)
    header = f"{'Ticket ID':<11} {'Device Name':<14} {'IP Address':<18} {'Status':<10} {'Issue Type':<16}"
    print(header)
    print("-" * len(header))
    for t in tickets:
        if t.get("issue_type") == ISSUE_TYPE:
            print(
                f"{t['ticket_id']:<11} {t['device_name']:<14} {t['ip_address']:<18} "
                f"{t.get('status', ''):<10} {t.get('issue_type', ''):<16}"
            )
    print("=" * 70)


def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices = get_affected_devices()
    tickets = get_tickets()

    print("=" * 70)
    print("AUTOMATED DNS REMEDIATION")
    print("Detect altered DNS -> Notify stakeholders -> Correct -> Update ticket")
    print("=" * 70)

    for device in devices:
        name = device["Device Name"]
        ip = device["Device Address"]

        print(f"\n{'=' * 70}")
        print(f"DEVICE: {name} ({ip})")
        print(f"{'=' * 70}")

        current_dns = detect_altered_dns(device)

        subject, body = build_altered_email(device, current_dns, ", ".join(EXPECTED_DNS), timestamp)
        send_email(subject, body)

        correct_dns(device)

        print(f"\n  --- Updating Ticket in Web Service ---")
        ticket = find_ticket(tickets, device)
        if ticket is None:
            print(f"  No open {ISSUE_TYPE} ticket found for {name}; creating one...")
            created = create_ticket(device)
            if created:
                ticket_id = created.get("ticket_id")
                open_ticket = {"ticket_id": ticket_id, "device_name": name, "ip_address": ip}
                tickets.append(open_ticket)
            else:
                ticket_id = None
        else:
            ticket_id = ticket["ticket_id"]

        if ticket_id is not None:
            resolve_ticket(ticket_id, device, timestamp)

    tickets = get_tickets()
    show_ticket_entries(tickets)


if __name__ == "__main__":
    main()
