import asyncio
import json
import shutil
import sys
import os
import uuid
from database import DatabaseManager

class ScanOrchestrator:
    def __init__(self):
        self.binaries = {
            "subfinder": shutil.which("subfinder"),
            "httpx": shutil.which("httpx"),
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
        
        LARGE_LIMIT = 25 * 1024 * 1024
        
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=LARGE_LIMIT
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
    
    # Must accept BOTH domain and session ID from app.py
    if len(sys.argv) < 3:
        print("[-] Usage: python orchestrator.py <domain> <session_id>")
        sys.exit(1)
        
    target_domain = sys.argv[1]  
    session_id = sys.argv[2]
    
    # Create isolated workspace for this specific scan session
    workspace = f"scans_{uuid.uuid4().hex[:8]}"
    os.makedirs(workspace, exist_ok=True)
    
    target_file = f"{workspace}/temp_subdomains.txt"
    alive_file = f"{workspace}/alive_hosts.txt"
    output_file = f"{workspace}/crawled_endpoints.txt"
    
    print(f"\n--- [1/4] Starting Passive Recon on {target_domain} ---")
    subfinder_args = ["-d", target_domain, "-silent", "-json"]
    raw_subdomains = []
    
    async for output_line in orchestrator.execute_tool("subfinder", subfinder_args):
        try:
            data = json.loads(output_line)
            host = data.get('host')
            if host:
                raw_subdomains.append(host)
        except json.JSONDecodeError:
            pass

    if not raw_subdomains:
        print("[-] No subdomains found. Halting pipeline.")
        return

    with open(target_file, "w") as f:
        for sub in raw_subdomains:
            f.write(f"{sub}\n")
            
    print(f"\n--- Saved {len(raw_subdomains)} raw hosts. ---")

    print(f"\n--- [2/4] Filtering {len(raw_subdomains)} domains for ALIVE web servers ---")
    httpx_args = ["-l", target_file, "-silent", "-json"]
    alive_hosts = []

    async for output_line in orchestrator.execute_tool("httpx", httpx_args):
        try:
            data = json.loads(output_line)
            url = data.get('url')
            if url:
                alive_hosts.append(url)
                print(f"[HTTPX] Alive: {url}")
        except json.JSONDecodeError:
            pass

    with open(alive_file, "w") as f:
        for host in alive_hosts:
            f.write(f"{host}\n")

    print(f"\n--- Saved {len(alive_hosts)} ALIVE hosts. ---")
   
    print(f"\n--- [3/4] Crawling {len(alive_hosts)} ALIVE hosts ---")
    katana_args = [
        "-list", alive_file, 
        "-jc",
        "-d", "2",
        "-fs", "rdn",
        "-ef", "css,png,jpg,jpeg,svg,gif,woff,woff2,ico,pdf,zip",
        "-c", "200",
        "-jsonl"
    ]
        
    unique_endpoints = set()
    ignored_extensions = ('.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.woff', '.woff2', '.ico')

    async for output_line in orchestrator.execute_tool("katana", katana_args):
        try:
            data = json.loads(output_line)
            endpoint = data.get('request', {}).get('endpoint') or data.get('url')
            
            if endpoint:
                if target_domain not in endpoint:
                    continue
                
                base_url = endpoint.split('?')[0].lower()
                if base_url.endswith(ignored_extensions):
                    continue
                
                if endpoint not in unique_endpoints:
                    unique_endpoints.add(endpoint)
                    print(f"[Filtered Katana] Unique Endpoint: {endpoint}")
                    
        except json.JSONDecodeError:
            pass

    with open(output_file, "w") as f:
        for url in unique_endpoints:
            f.write(f"{url}\n")
            
    print(f"\n--- Phase 3 Complete. Saved {len(unique_endpoints)} clean endpoints. ---")
 
    print(f"\n--- [4/4] Starting Vulnerability Scan with Nuclei ---")

    db = DatabaseManager()
    
    # Pass session_id to database to link this scan to the user's browser!
    scan_id = db.start_scan(target_domain, session_id)

    nuclei_args = [
        "-list", alive_file,
        "-tags", "tech,exposure,misconfig",
        "-c", "100",
        "-bs", "100",            
        "-rl", "500",             
        "-timeout", "4",
        "-retries", "0",
        "-max-host-error", "5",
        "-silent",
        "-jsonl"
    ]

    vuln_count = 0

    async for output_line in orchestrator.execute_tool("nuclei", nuclei_args):
        try:
            vuln_data = json.loads(output_line)

            vuln_id = vuln_data.get("template-id", "unknown")
            vuln_name = vuln_data.get("info", {}).get("name", "Unknown Vulnerability")
            
            # Syntax fixed here to prevent python crash
            severity = vuln_data.get("info", {}).get("severity", "info").upper()
            matched_url = vuln_data.get("matched-at", "unknown url")

            db.save_vulnerability(scan_id, vuln_id, vuln_name, severity, matched_url)
            vuln_count += 1

            print(f"[{severity}] Saved to DB: {vuln_name} -> {matched_url}")
        except json.JSONDecodeError:
            pass

    
    db.complete_scan(scan_id)

    print(f"\n[+] Full pipeline finished! Saved {vuln_count} findings to scanner.db.")

if __name__ == "__main__":
    asyncio.run(main())