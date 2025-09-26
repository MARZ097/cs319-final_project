import os
import subprocess
import threading
import time

def run_command(command):
    subprocess.run(command, shell=True)

def run_flask():
    print("Starting Flask server...")
    flask_env = os.environ.copy()
    subprocess.run("venv\\Scripts\\activate && flask run", shell=True, env=flask_env)

def run_tailwind():
    print("Installing npm packages...")
    subprocess.run("npm install", shell=True)
    
    print("Building Tailwind CSS...")
    subprocess.run("npm run build", shell=True)
    
    print("Starting Tailwind watcher...")
    subprocess.run("npm run watch", shell=True)

if __name__ == "__main__":
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Run Tailwind in the main thread
    run_tailwind()
