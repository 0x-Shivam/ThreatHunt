import asyncio
import json
import shutil
import sys

class ScanOrchestrator:
    def __init__(self):
        # Verify the binaries \


        self.binaries = {
            "subfinder": shutil.which("subfinder"),
            "katana": shutil.which("katana"),
            "nuclei": shutil.which("nuclei")

        }
        self.validate_environment()

    def validate_environment(self):
        """Ensures all required third-party tools are installed and accessible."""
        missing = [name for name, path in self.binaries.items() if not path]
        if missing:
            print(f"[-] Critical Error: Missing binaries in PATH: {', '.join(missing)}")
            print("[*] Please ensure they are installed and globally accessible.")
            sys.exit(1)
        print("[+] Environment check passed. All binaries found.")

    async def execute_tool(self, tool_name: str, arguments: list):

        """
        Executes a binary asynchronously and yields its output line by line.
        This prevents the engine from blocking while waiting for a heavy scan.
        """
        binary_path = self.binaries.get(tool_name)
        command = [binary_path] + arguments
        


        print(f"[*] Launching: {' '.join(command)}")
        
        # Start the async subprocess


        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL 


        )

        # Read the standard output line by line as it streams in real-time
        while True:
            line = await process.stdout.readline()
            if not line:


                break
            
            yield line.decode('utf-8').strip()

        await process.wait()
        print(f"[+] Component '{tool_name}' finished execution.")

# Example Usage:
async def main():
    orchestrator = ScanOrchestrator()
    
    # Test target
    target_domain = "instacart.com"
    
    # Arguments for subfinder to output silent raw JSON data lines

    subfinder_args = ["-d", target_domain, "-silent", "-json"]
    
    print(f"\n---[1/2] Starting Passive Recon on {target_domain} ---")
    async for output_line in orchestrator.execute_tool("subfinder", subfinder_args):
        try:
            data = json.loads(output_line)
            host = data.get('host')
            if host:
                discovered_subdomains.append(host)
                print(f"[Subfinder] Discovered: {host}")
        except json.JSONDecodeError:
            pass
        # halt if nothing was found 

        if not discovered_subdomains:
            print("[-] No Subdomains found. Halting pipeline.")
            return
        
        # save to a temporary file for katana to read 

        target_file = "temp_subdomains.txt"
        with open(target_file, "w") as f:
            for sub in discovered_subdomains:
                f.write(f"{sub}\n")

        print(f"\n--- [2/2] Saved {len(discovered_subdomains)} hosts. Launching Katana ---")

        # 4. Run Katana using the subdomains file
            # -jc crawls javascript files for hidden API endpoints

        katana_args = ["-list", target_file, "-jc", "-jsonly"]

        async for output_line in orchestrator.execute_tool("katana", katana_args):
            try:
                data = json.loads(output_line)

                endpoint = data.get('request', {}).get('endpoint') or data.get('url', 'Unknown URL')
                print(f"[Katana] Crawled Endpoint:{endpoint}")
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    asyncio.run(main())
    
                

           