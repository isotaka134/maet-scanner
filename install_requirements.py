import subprocess
import sys

def install_packages():
    try:
        # Upgrade pip first
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
        
        # Install packages from requirements.txt
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        
        print("All required packages have been installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while installing packages: {e}")

if __name__ == "__main__":
    install_packages()
