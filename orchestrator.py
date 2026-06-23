import asyncio
import json
import shutil
import sys
from database import DatabaseManager


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
        Includes an increased buffer limit to handle massive minified JS/JSON outputs.
        """
        binary_path = self.binaries.get(tool_name)
        command = [binary_path] + arguments
        
        print(f"[*] Launching: {' '.join(command)}")
        
        # Increase the limit to 25MB (25 * 1024 * 1024) to handle giant target outputs
        LARGE_LIMIT = 25 * 1024 * 1024
        
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=LARGE_LIMIT # <--- THIS FIXES THE CRASH
        )

        while True:
            line = await process.stdout.readline()
            if not line:
                break
            
            yield line.decode('utf-8', errors='ignore').strip()

        await process.wait()
        print(f"[+] Component '{tool_name}' finished execution.")

async def main():
    orchestrator = ScanOrchestrator()
    target_domain = "example.com"  
    
    # 1. Run Subfinder
    subfinder_args = ["-d", target_domain, "-silent", "-json"]
    discovered_subdomains = []
    
    print(f"\n--- [1/3] Starting Passive Recon on {target_domain} ---")
    async for output_line in orchestrator.execute_tool("subfinder", subfinder_args):
        try:
            data = json.loads(output_line)
            host = data.get('host')
            if host:
                discovered_subdomains.append(host)
        except json.JSONDecodeError:
            pass

    if not discovered_subdomains:
        print("[-] No subdomains found. Halting pipeline.")
        return

    target_file = "temp_subdomains.txt"
    with open(target_file, "w") as f:
        for sub in discovered_subdomains:
            f.write(f"{sub}\n")
            
    print(f"\n--- [2/3] Saved {len(discovered_subdomains)} hosts. Launching Filtered Katana ---")

    # 2. Run Katana with filters
    katana_args = ["-list", target_file, "-jc", "-jsonl"]
    
    # Use sets to keep tracking unique endpoints and avoid duplicates in memory
    unique_endpoints = set()
    ignored_extensions = ('.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.woff', '.woff2', '.ico')

    async for output_line in orchestrator.execute_tool("katana", katana_args):
        try:
            data = json.loads(output_line)
            endpoint = data.get('request', {}).get('endpoint') or data.get('url')
            
            if endpoint:
                # Rule 1: Ensure it's strictly in-scope (belongs to your target domain)
                if target_domain not in endpoint:
                    continue
                
                # Rule 2: Clean parameters out to check the base extension safely
                base_url = endpoint.split('?')[0].lower()
                if base_url.endswith(ignored_extensions):
                    continue
                
                # Rule 3: Deduplicate identical endpoints
                if endpoint not in unique_endpoints:
                    unique_endpoints.add(endpoint)
                    print(f"[Filtered Katana] Unique Endpoint: {endpoint}")
                    
        except json.JSONDecodeError:
            pass

    # 3. Save clean endpoints for Phase 3 (Nuclei Scanning)
    output_file = "crawled_endpoints.txt"
    with open(output_file, "w") as f:
        for url in unique_endpoints:
            f.write(f"{url}\n")
            
    print(f"\n--- [3/3] Phase 2 Complete. Saved {len(unique_endpoints)} clean endpoints to {output_file} ---")


    # NUCLEI SCANNING ENGINE and DB
    print(f"\n--- Starting Vulnerability Scan with nuclei ---")

    # Initialize DB  and start scan session 

    db= DatabaseManager()
    scan_id = db.start_scan(target_domain)

    nuclei_args = [
        "-list", output_file,
        "-tags", "tech,exposure,misconfig",
        "-silent",
        "-jsonl"
    ]

    vuln_count = 0
    async for outputline in orchestrator.execute_tool("nuclei", nuclei_args):
        try:
            vuln_data = json.loads(outputline)

            # Extract details
            vuln_id = vuln_data.get("template-id", "unknown")
            vuln_name = vuln_data.get("info", {}).get("name", "Unknown Vulnerability")
            severity = vuln_data.get("info", {}).get("severity", "info").upper()
            matched_url = vuln_data.get("matched-at", "unknown url")

            # save at sqlite db 
            db.save_vulnerability(scan_id, vuln_id, vuln_name, severity, matched_url)
            vuln_count += 1

            print(f"[{severity}] Saved to DB: {vuln_name} -> {matched_url}")
        except json.JSONDecodeError:
            pass


        # Mark scan as finished in the DB
        db.complete_scan(scan_id)

    print(f"\n[+] Full pipeline finished! Saved {vuln_count} findings to scanner.db.")
if __name__ == "__main__":
    asyncio.run(main())

