import subprocess
import os
import sys

def check_for_updates(current_version):
    latest_version = "1.5" 
    return latest_version != current_version

def update_package(current_version):
    print("Checking for updates...")
    
    if check_for_updates(current_version):
        print("A new version is available! Updating...")
        try:
         
            subprocess.check_call([sys.executable, "setup.py", "sdist", "bdist_wheel"])
            subprocess.check_call([sys.executable, "-m", "pip", "install", ".", "--upgrade"])
            print("Update successful!")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred during the update: {e}")
    else:
        print("You are already on the latest version.")

if __name__ == "__main__":
    current_version = "1.4" 
    update_package(current_version)

