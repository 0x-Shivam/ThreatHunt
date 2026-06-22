import asyncio
import json
import shutil
import sys 

class ScanOrchestrator:
    def __init__(self):
        # Verify the binaries
        self.binaries = {
            "subfinder": shutil.which("subfinder"),
            "katana": shutil.which("katana"),
            "nuclei": shutil.which("nuclei")
        }

        self.validate_environment()

        def validate_environment(self):
            """Ensures all required third-party tools are installed and accessible"""
            missing = [name for name, path in self.binaries.items() if not path]

            if missing:
                print(f"[-] Critical Error: Missing binaries in PATH: {', '.join(missing)}")

                print("[*] Please ensure they are installed and globally accessible.")
                sys.exit(1)

                print("[+] Environment check passed. All binaries found.")
                

        

