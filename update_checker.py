import subprocess
import os
import sys

def check_for_updates(current_version):
    
    latest_version = "1.2"  
    return latest_version != current_version

def update_package():
    print("Checking for updates...")
    current_version = "1.2"
    if check_for_updates(current_version):
        print("A new version is available! Updating...")
        subprocess.call([sys.executable, "setup.py", "sdist", "bdist_wheel"])
        subprocess.call([sys.executable, "-m", "pip", "install", ".", "--upgrade"])
        print("Update successful!")
    else:
        print("You are already on the latest version.")

if __name__ == "__main__":
    update_package()
