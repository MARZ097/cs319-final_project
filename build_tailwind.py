import os
import subprocess
import sys

def build_tailwind():
    """Build Tailwind CSS"""
    print("Building Tailwind CSS...")
    try:
        # Check if Node.js is installed
        node_version = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if node_version.returncode != 0:
            print("Error: Node.js is not installed. Please install Node.js to build Tailwind CSS.")
            return False
        
        # Check if npm packages are installed
        if not os.path.exists('node_modules'):
            print("Installing npm packages...")
            subprocess.run(['npm', 'install'], check=True)
        
        # Build Tailwind CSS
        print("Running Tailwind build...")
        subprocess.run(['npx', 'tailwindcss', '-i', './app/static/src/input.css', '-o', './app/static/css/tailwind.css', '--minify'], check=True)
        
        print("Tailwind CSS built successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error building Tailwind CSS: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False

if __name__ == "__main__":
    # Run as a standalone script
    success = build_tailwind()
    sys.exit(0 if success else 1)
