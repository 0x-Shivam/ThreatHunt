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

    async def execute_tool(self, tool_name: str, arguments: list):
        """
        Executes a binary asynchronously and yields its output line by line.
        This prevents the engine from blocking while waiting for heavy scan.
        """

        binary_path = self.binaries.get(tool_name)
        command = [binary_path] + arguments


        print(f"[*] Launching: {' '.join(command)}")

        # Start the async subprocess

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE
            stderr=asyncio.subprocess.DEVNULL
        )


        # Read the standard output line by line as it streams in real-time

        while True:
            line = await process.stdout.readline()
            if not line:
                break

            yield line.decode('utf-8').strip()

            

