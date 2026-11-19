#!/usr/bin/env python3
"""CI-only SSH login to Cowrie's FAKE shell; no real systems or credentials.

Connects only to docker-compose service name "cowrie" on private bridge.
Does not forward connections, execute host commands or print credentials.
"""
import json
import socket
import time
import paramiko


def fake_shell_session():
    client=paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # This password is synthetic and valid only for the disposable fake shell.
    # Cowrie's userdb may reject the first attempt depending on config.
    failures=0
    try:
        for i in range(1,5):
            try:
                client.connect("cowrie", port=2222, username="root",
                               password="CI-FAKE-SHELL-ONLY-42",
                               allow_agent=False, look_for_keys=False,
                               timeout=9, auth_timeout=9, banner_timeout=9)
                break
            except paramiko.AuthenticationException:
                failures+=1
                time.sleep(0.5)
        else:
            raise AssertionError("Cowrie fake-shell login was not accepted")
        channel=client.invoke_shell(width=80,height=24)
        channel.settimeout(3)
        time.sleep(1)
        # A harmless simulated command. Output is never printed.
        channel.sendall("whoami\n")
        time.sleep(2)
        channel.sendall("exit\n")
        time.sleep(1)
        channel.close()
        return {"ssh_authentication":"accepted_by_fake_cowrie_shell",
                "synthetic_command":"sent_and_recorded_by_cowrie",
                "authentication_rejections_before_accept":failures,
                "production_host_contacted":False,
                "real_password_used":False}
    finally:
        client.close()


if __name__=="__main__":
    print(json.dumps(fake_shell_session(),sort_keys=True))
