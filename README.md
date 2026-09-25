import json
import os
import sys
import urllib.error
import urllib.request
from config import HELPDESK_BASE_URL, HELPDESK_TOKEN

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enumerate_devices import enumerate_devices
from monitor_device_availability import has_static_ip, ping_device

CSV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_devices.csv")
TICKET_URL = f"{HELPDESK_BASE_URL}/api/tickets"
ISSUE_TYPE = "Device Unavailable"


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
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {"message": raw}

    except urllib.error.HTTPError as e:
        # Read the error body safely even if it is not valid JSON (e.g. 500/502 HTML pages)
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"error": raw.strip()}

    except urllib.error.URLError as e:
        return None, {"error": str(e.reason)}


def main():
    devices = enumerate_devices(CSV_FILE)

    print("=" * 65)
    print("DEVICE UNAVAILABILITY TICKETING")
    print(f"Issue type: {ISSUE_TYPE}")
    print(f"Ticket service: {TICKET_URL}")
    print("=" * 65)

    created = 0
    failed = 0

    for d in devices:
        address = d["Device Address"]
        if not has_static_ip(address):
            print(f"[SKIP] {d['Device Name']:<8} | {address:<18} | No static IP (not monitored)")
            continue
        if not ping_device(address):
            name = d["Device Name"]
            status, response = create_ticket(d)

            if status == 201:
                ticket = response.get("ticket_id", "?")
                print(f"[OK]   Ticket #{ticket} | {name:<8} | {address:<18} | {response.get('message', '')}")
                created += 1
            else:
                # ----------------- ERROR EXTRACTION -----------------
                # Check all typical error keys used by REST APIs
                if isinstance(response, dict):
                    err_msg = (
                        response.get("error")
                        or response.get("message")
                        or response.get("detail")
                        or response.get("errors")
                        or str(response)
                    )
                else:
                    err_msg = str(response)

                status_prefix = f"HTTP {status}: " if status else "Network Error: "
                print(f"[FAIL] {name:<8} | {address:<18} | {status_prefix}{err_msg}")
                # ----------------------------------------------------
                failed += 1

    print("-" * 65)
    print(f"Total: {created} tickets created, {failed} failed")
    print("=" * 65)


if __name__ == "__main__":
    main()
