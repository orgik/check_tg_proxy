import paramiko
import os
import sys
import time

HOST = "194.87.110.184"
USER = "root"
PASSWORD = "bXzP7hmE2h"
REMOTE_DIR = "/opt/cheker"
LOCAL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ssh_connect():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASSWORD, timeout=15)
    return ssh


def run_cmd(ssh, cmd, timeout=120):
    print(f">>> {cmd[:120]}")
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    exit_code = stdout.channel.recv_exit_status()
    if out.strip():
        safe = out.strip().encode("ascii", errors="replace").decode("ascii")
        print(safe[-500:] if len(safe) > 500 else safe)
    if err.strip():
        safe = err.strip().encode("ascii", errors="replace").decode("ascii")
        print(f"STDERR: {safe[-300:]}")
    if exit_code != 0:
        print(f"EXIT CODE: {exit_code}")
    return out, err, exit_code


def upload_file(sftp, local_path, remote_path):
    print(f"  Upload: {local_path} -> {remote_path}")
    sftp.put(local_path, remote_path)


def upload_dir(sftp, local_dir, remote_dir):
    for item in os.listdir(local_dir):
        local_path = os.path.join(local_dir, item)
        remote_path = f"{remote_dir}/{item}"
        if os.path.isfile(local_path):
            if item.endswith((".pyc", ".pyo")) or item == "__pycache__":
                continue
            upload_file(sftp, local_path, remote_path)
        elif os.path.isdir(local_path):
            if item in ("__pycache__", ".git", "venv", "data", ".env"):
                continue
            try:
                sftp.mkdir(remote_path)
            except IOError:
                pass
            upload_dir(sftp, local_path, remote_path)


def main():
    ssh = ssh_connect()

    print("\n=== Step 1: Install system packages ===")
    run_cmd(ssh, "apt-get update -qq", timeout=120)
    run_cmd(ssh, "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv python3-pip python3-dev build-essential nginx libffi-dev libssl-dev git", timeout=300)

    print("\n=== Step 2: Create project directory ===")
    run_cmd(ssh, f"mkdir -p {REMOTE_DIR}/app/checks {REMOTE_DIR}/app/routers {REMOTE_DIR}/app/client_hello {REMOTE_DIR}/static/css {REMOTE_DIR}/static/js {REMOTE_DIR}/templates {REMOTE_DIR}/deploy {REMOTE_DIR}/data")

    print("\n=== Step 3: Upload project files ===")
    sftp = ssh.open_sftp()
    upload_dir(sftp, LOCAL_DIR, REMOTE_DIR)
    sftp.close()

    print("\n=== Step 4: Clone client_hello files from tls_handshake_check ===")
    run_cmd(ssh, f"""
        cd /tmp && rm -rf tls_handshake_check && \
        git clone --depth 1 https://github.com/izmmisha/tls_handshake_check.git && \
        cp -r tls_handshake_check/client_hello/* {REMOTE_DIR}/app/client_hello/ && \
        ls -la {REMOTE_DIR}/app/client_hello/
    """, timeout=60)

    print("\n=== Step 5: Create Python venv and install dependencies ===")
    run_cmd(ssh, f"cd {REMOTE_DIR} && python3 -m venv venv", timeout=60)
    run_cmd(ssh, f"cd {REMOTE_DIR} && venv/bin/pip install --upgrade pip", timeout=60)
    run_cmd(ssh, f"cd {REMOTE_DIR} && venv/bin/pip install -r requirements.txt", timeout=300)

    print("\n=== Step 6: Create .env file ===")
    import secrets
    secret_key = secrets.token_hex(32)
    run_cmd(ssh, f"""cat > {REMOTE_DIR}/.env << 'ENVEOF'
ADMIN_PASSWORD=admin123
SECRET_KEY={secret_key}
DATABASE_PATH={REMOTE_DIR}/data/cheker.db
MAX_CONCURRENT_CHECKS=5
CHECK_TIMEOUT=30
ENVEOF""")

    print("\n=== Step 7: Setup nginx ===")
    run_cmd(ssh, f"cp {REMOTE_DIR}/deploy/nginx.conf /etc/nginx/sites-available/cheker")
    run_cmd(ssh, "ln -sf /etc/nginx/sites-available/cheker /etc/nginx/sites-enabled/cheker")
    run_cmd(ssh, "rm -f /etc/nginx/sites-enabled/default")
    run_cmd(ssh, "nginx -t")
    run_cmd(ssh, "systemctl restart nginx")

    print("\n=== Step 8: Setup systemd service ===")
    run_cmd(ssh, f"cp {REMOTE_DIR}/deploy/cheker.service /etc/systemd/system/")
    run_cmd(ssh, "systemctl daemon-reload")
    run_cmd(ssh, "systemctl enable cheker")
    run_cmd(ssh, "systemctl restart cheker")

    print("\n=== Step 9: Verify ===")
    time.sleep(2)
    run_cmd(ssh, "systemctl status cheker --no-pager")
    run_cmd(ssh, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/ || echo 'FAIL'")

    ssh.close()
    print(f"\n=== Done! Visit http://{HOST}/ ===")


if __name__ == "__main__":
    main()
