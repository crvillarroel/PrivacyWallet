import os, sys
import shutil
import pathlib
import subprocess as sp
from pathlib import Path

from spur.results import ExecutionResult

import spurplus
from spurplus import SshShell

from typing import Union, Optional

from invoke import task
from invoke import Collection

sh: SshShell = None


def get_shell(production=False) -> SshShell:

    global sh
    if sh is not None:
        return sh

    if production:
        hostname = "safeisland.hesusruiz.org"
        print(f"=== Operating in PRODUCTION!! ({hostname})")
    else:
        hostname = "safeisland.hesusruiz.org"
        print(f"=== Operating in TESTING!! ({hostname})")

    sh = spurplus.connect_with_retries(
        hostname=hostname,
        username='ubuntu',
        private_key_file='/home/jesus/aws/AWSAlastriaIN2.pem',
        retries=5,
        connect_timeout=5,
        )
    return sh


def compare(sh: SshShell, local_path: Union[str, pathlib.Path], remote_path: Union[str, pathlib.Path]) -> int:

    diff = sh.directory_diff(local_path, remote_path)

    if len(diff.differing_files) > 0:
        print("\n   => Differing files")
        for f in diff.differing_files:
            print(f"  {f.name}")

    if len(diff.local_only_files) > 0:
        print("\n   => Local Only")
        for f in diff.local_only_files:
            print(f"  {f.name}")

    num_diffs = len(diff.differing_files) + len(diff.local_only_files) + len(diff.remote_only_files)
    return num_diffs


################################################
# NGINX
################################################

@task
def restartx(c, production=False):
    """Restart NGINX
    """

    sh = get_shell(production)

    result = sh.run(["sudo", "systemctl", "restart", "nginx"],
        cwd="/home/ubuntu", stdout=sys.stdout, stderr=sys.stderr,
        allow_error=True)

    if result.return_code != 0:
        print(f"==== Error =====\n{result.stderr_output}")
        return

    print(f"NGINX restarted")        



@task
def restart(c, production=False):
    """Restart the gunicorn server
    """

    sh = get_shell(production)

    result = sh.run(["pkill", "-HUP", "-F", "gunicorn.pid"],
        cwd="/home/ubuntu/wallet",
        allow_error=True)

    if result.return_code != 0:
        print(f"==== Error =====\n{result.stderr_output}")
        return

    print(f"Gunicorn restarted")



@task
def start(c, production=False):
    """Start the server
    """

    sh = get_shell(production)

    cmd_start = ["/home/ubuntu/.local/bin/gunicorn", "--daemon", "-p", "gunicorn.pid", "wsgip4w:application"]
    result = sh.run(cmd_start,
        cwd="/home/ubuntu/wallet", stdout=sys.stdout, stderr=sys.stderr,
        allow_error=True)

    if result.return_code != 0:
        print(f"==== Error =====\n{result.stderr_output}")
        return

    print(f"{result.output}")


@task
def stop(c, production=False):
    """Stop the gunicorn server
    """

    sh = get_shell(production)

    result = sh.run(["pkill", "-F", "gunicorn.pid"],
        cwd="/home/ubuntu/wallet", stdout=sys.stdout, stderr=sys.stderr,
        allow_error=True)

    if result.return_code != 0:
        print(f"==== Error =====\n{result.stderr_output}")
        return

    print(f"{result.output}")



@task
def check(c, production=False):
    """Check if gunicorn is running
    """
    sh = get_shell(production)

    result = sh.run(["ps", "-C", "gunicorn"],
        cwd="/home/ubuntu/wallet",
        allow_error=True)        

    if result.return_code == 1:
        print(f"Gunicorn not running")
    elif result.return_code == 0:
        print(f"{result.output}")
    else:
        print(f"Return code: {result.return_code}")


@task
def upload(c, production=False):
    """Update the wallet and upgrade service worker
    """

    # Copy "index.html" to "verifier.html", "pubcred.html", "admin.html" and "demo.html"
    # They are convenience methods to invoke special functionality
    e = shutil.copy2("www/index.html", "www/verifier.html")
    print(f"Copied {e}")
    e = shutil.copy2("www/index.html", "www/pubcred.html")
    print(f"Copied {e}")
    e = shutil.copy2("www/index.html", "www/admin.html")
    print(f"Copied {e}")
    e = shutil.copy2("www/index.html", "www/demo.html")
    print(f"Copied {e}")

    # Update locally the workbox files
    c.run("workbox generateSW workbox-config.js")

    sh = get_shell(production)

    print("\n==> Synchronize testing frontend files")

    local_dir = "www/"
    remote_dir = "ubuntu@safeisland:/var/www/safeisland.hesusruiz.org/html"

    rsync_args = ["rsync",
        "-a",   # same as -rlptgoD: recurse, preserve links, permissions, modification times, group, owner, special files
        "-u",   # skip files which exist on the destination and have a modified time that is newer than the source file
        "-z",   # compress when transmitting
        "-i",   # output a change-summary for all updates
        "--exclude-from=rsync_exclude.txt",
        local_dir,
        remote_dir
    ]
    result = sp.run(rsync_args, capture_output=False, text=True, check=False)

@task
def uploaddev(c, production=False):
    """Development: Update just the wallet
    """
    
    sh = get_shell(production)

    print("\n==> Synchronize testing frontend files")

    local_dir = "www/"
    remote_dir = "ubuntu@safeisland:/var/www/safeisland.hesusruiz.org/html"

    rsync_args = ["rsync",
        "-a",   # same as -rlptgoD: recurse, preserve links, permissions, modification times, group, owner, special files
        "-u",   # skip files which exist on the destination and have a modified time that is newer than the source file
        "-z",   # compress when transmitting
        "-i",   # output a change-summary for all updates
        "--exclude-from=rsync_exclude.txt",
        local_dir,
        remote_dir
    ]
    result = sp.run(rsync_args, capture_output=False, text=True, check=False)

@task
def uploadgene(c, production=False):
    """GENCAT - Update the wallet and upgrade service worker
    """

    # Copy "index.html" to "verifier.html", "pubcred.html", "admin.html" and "demo.html"
    # They are convenience methods to invoke special functionality
    e = shutil.copy2("www/index.html", "www/verifier.html")
    print(f"Copied {e}")
    e = shutil.copy2("www/index.html", "www/pubcred.html")
    print(f"Copied {e}")
    e = shutil.copy2("www/index.html", "www/admin.html")
    print(f"Copied {e}")
    e = shutil.copy2("www/index.html", "www/demo.html")
    print(f"Copied {e}")

    # Update locally the workbox files
    c.run("workbox generateSW workbox-config.js")

    sh = get_shell(production)

    print("\n==> Synchronize testing frontend files")

    local_dir = "www/"
    remote_dir = "ubuntu@safeisland:/var/www/gencat.hesusruiz.org/html"

    rsync_args = ["rsync",
        "-a",   # same as -rlptgoD: recurse, preserve links, permissions, modification times, group, owner, special files
        "-u",   # skip files which exist on the destination and have a modified time that is newer than the source file
        "-z",   # compress when transmitting
        "-i",   # output a change-summary for all updates
        "--exclude-from=rsync_exclude.txt",
        local_dir,
        remote_dir
    ]
    result = sp.run(rsync_args, capture_output=False, text=True, check=False)

