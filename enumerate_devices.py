import csv
import os
import re
import shutil
import subprocess
import sys

from config import (
    VYOS_SSH_HOST,
    VYOS_SSH_PORT,
    VYOS_USERNAME,
    VYOS_PASSWORD,
)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "network_devices.csv")

IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def enumerate_devices(csv_path):
    devices = []

    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            devices.append(row)

    # Find devices whose address comes from DHCP
    dhcp_rows = [
        device
        for device in devices
        if device["Device Address"].strip().upper() == "DHCP"
    ]

    if not dhcp_rows:
        return devices

    try:
        leases = get_dhcp_leases()

    except Exception as exc:
        print(
            f"[WARN] DHCP lookup failed; "
            f"{len(dhcp_rows)} DHCP device(s) will remain unresolved: {exc}",
            file=sys.stderr,
        )
        return devices

    # Replace DHCP with the currently assigned address
    for row in dhcp_rows:
        device_name = row["Device Name"].strip().lower()

        resolved = leases.get(device_name)

        if resolved:
            row["Device Address"] = resolved
        else:
            print(
                f"[WARN] No DHCP lease found for "
                f"'{row['Device Name']}'.",
                file=sys.stderr,
            )

    return devices

def print_devices(devices):
    header = (
        f"{'Device ID':<12} "
        f"{'Name':<14} "
        f"{'Address':<16} "
        f"{'Subnet Mask':<18} "
        f"{'Location':<12} "
        f"{'Port':<6} "
        f"{'OS':<14}"
    )

    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for device in devices:
        print(
            f"{device['Device ID']:<12} "
            f"{device['Device Name']:<14} "
            f"{device['Device Address']:<16} "
            f"{device['Subnet Mask']:<18} "
            f"{device['Location']:<12} "
            f"{device['Access Port']:<6} "
            f"{device['OS']:<14}"
        )

    print("=" * len(header))
    print(f"Total devices: {len(devices)}")

def get_dhcp_leases():
    """
    Retrieve the current DHCP lease table from ROUTER1.
    """

    if shutil.which("sshpass") and VYOS_PASSWORD:
        output = _run_leases_via_sshpass()
    else:
        output = _run_leases_via_paramiko()

    return parse_leases(output)


def _vyos_script():
    """
    Commands sent to VyOS through vbash.
    """
    return """source /opt/vyatta/etc/functions/script-template
run show dhcp server leases
exit
"""


def _run_leases_via_sshpass():
    argv = [
        "sshpass",
        "-p",
        VYOS_PASSWORD,
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=5",
        "-p",
        str(VYOS_SSH_PORT),
        f"{VYOS_USERNAME}@{VYOS_SSH_HOST}",
        "vbash -s",
    ]

    try:
        result = subprocess.run(
            argv,
            input=_vyos_script(),
            capture_output=True,
            text=True,
            timeout=15,
        )

    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"SSH to {VYOS_USERNAME}@"
            f"{VYOS_SSH_HOST}:{VYOS_SSH_PORT} timed out"
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"SSH to {VYOS_USERNAME}@"
            f"{VYOS_SSH_HOST}:{VYOS_SSH_PORT} failed: "
            f"{result.stderr.strip() or result.returncode}"
        )

    return result.stdout

def _run_leases_via_paramiko():
    try:
        import paramiko

    except ImportError as exc:
        raise RuntimeError(
            "Neither sshpass nor paramiko is available."
        ) from exc

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:
        client.connect(
            hostname=VYOS_SSH_HOST,
            port=int(VYOS_SSH_PORT),
            username=VYOS_USERNAME,
            password=VYOS_PASSWORD,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )

        # IMPORTANT:
        # VyOS operational commands must be run through vbash.
        stdin, stdout, stderr = client.exec_command(
            "vbash -s",
            timeout=10,
        )

        stdin.write(_vyos_script())
        stdin.flush()

        # Tell VyOS there is no more input
        stdin.channel.shutdown_write()

        output = stdout.read().decode(
            errors="replace"
        )

        errors = stderr.read().decode(
            errors="replace"
        ).strip()

        if not output.strip() and errors:
            raise RuntimeError(
                f"VyOS DHCP command failed: {errors}"
            )

        return output

    finally:
        client.close()


def parse_leases(output):
    """
    Convert the VyOS DHCP table into:

    {
        "pc1": "192.168.10.101",
        "pc2": "192.168.20.100",
        ...
    }
    """
    leases = {}

    for line in output.splitlines():
        tokens = line.split()

        # A valid lease row has many columns.
        if len(tokens) < 3:
            continue

        ip = tokens[0]

        # Ignore headings and separator lines
        if not IP_PATTERN.match(ip):
            continue

        # VyOS columns end with:
        # Pool Hostname Origin
        hostname = tokens[-2].strip().lower()

        if not hostname or hostname == "hostname":
            continue

        leases[hostname] = ip

    return leases



def main():
    devices = enumerate_devices(CSV_FILE)

    print_devices(devices)


if __name__ == "__main__":
    main()