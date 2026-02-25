import os
import base64
import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from datetime import datetime


load_dotenv() 
console = Console() 

# --- FUNCTIONS ---
def get_clean_key(env_name):
    key = os.getenv(env_name, "")
    placeholders = ["", "none", "<your_api_key>", "your_api_key_here", "<your_gsb_api_key>"]
    
    if key and key.strip().lower() not in placeholders:
        return key.strip()
    return None
    
VT_API_KEY = get_clean_key("VT_API_KEY")
GSB_API_KEY = get_clean_key("GOOGLE_SAFE_BROWSING_KEY")

def check_setup(): 
    table = Table(title="[bold blue]System Diagnostic[/bold blue]", box=None)
    table.add_column("Security Engine", style="cyan")
    table.add_column("Status", justify="center")
 
    vt_status = "[bold green]✅ ACTIVE[/bold green]" if VT_API_KEY else "[bold red]❌ MISSING[/bold red]"
    table.add_row("VirusTotal", vt_status, "[green]Ready[/green]" if VT_API_KEY else "[red]Check .env[/red]")

    gsb_status = "[bold green]✅ ACTIVE[/bold green]" if GSB_API_KEY else "[bold red]❌ MISSING[/bold red]"
    table.add_row("Google Safe Browsing", gsb_status, "[green]Ready[/green]" if GSB_API_KEY else "[red]Check .env[/red]")

    console.print(table)
    
    active = []
    if VT_API_KEY: active.append("VirusTotal")
    if GSB_API_KEY: active.append("Google Safe Browsing")
    return active



def encode_url(target_url):
    """Convert URL to VirusTotal-compatible Base64 format"""
    # String to bytes
    url_bytes = target_url.encode("utf-8")
    # Base64 encoding (URL-safe)
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    # Bytes to string and strip padding (=)
    return base64_bytes.decode("utf-8").strip("=")


def fetch_vt_report(encoded_url):
    """Send a GET request to VirusTotal API to retrieve the URL report"""
    if not VT_API_KEY: return None
    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        return response.json()
    
    elif response.status_code == 404:
        console.print("[bold yellow]NOTICE:[/bold yellow] No report found.")
        return "NEW_URL"
    
    elif response.status_code == 401:
        console.print("[bold red]AUTHENTICATION ERROR:[/bold red] Invalid API Key. Check your .env file.")
        return None
    
    elif response.status_code == 429:
        console.print("[bold red]RATE LIMIT:[/bold red] You are sending too many requests. Please wait a bit.")
        return None

    elif response.status_code >= 500:
        console.print("[bold red]SERVER ERROR:[/bold red] VirusTotal servers are currently down. Try again later.")
        return None

    else:
        console.print(f"[bold red]UNKNOWN ERROR:[/bold red] Received status code {response.status_code}")
        return None
    

def parse_vt_results(report_data):
    """Extract and return key statistics from the raw JSON data"""
    attributes = report_data.get("data", {}).get ("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})

    flagged_by = []
    for engine_name, engine_data in results.items():
        if engine_data.get("category") in ["malicious", "suspicious"]:
            flagged_by.append({
                "engine": engine_name,
                "result": engine_data.get("result", "Unkown")
            })

    return stats, flagged_by

def display_vt_report(stats, flagged_by, url):
    """Create a visual table to display the scanning results to the user"""
    table = Table(title=f"\n[bold white on black] Scan Results for VirusTotal:[/bold white on black] [bold white on red] {url} [/bold white on red]")

    # Define table columns with specific alignments and colors
    table.add_column("Category", justify="left", style="cyan", no_wrap=True)
    table.add_column("Count", justify="center", style="magenta")
    table.add_column("Indicator", justify="right")

    # Extract individual stats from the dictionary
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)


    table.add_row("Malicious", str(malicious), "🚨 " if malicious > 0 else "✅")
    table.add_row("suspicious", str(suspicious), "⚠️ " if suspicious > 0 else "✅")
    table.add_row("harmless", str(harmless), "🛡️ " )
    console.print(table)

    if flagged_by:
        console.print("\n[bold yellow]VirusTotal Detailed Findings:[/bold yellow]")
        for item in flagged_by:
            console.print(f" [bold white]•[/bold white] [green]{item['engine']}[/green]: [red]{item['result']}[/red]")


def is_valid_url(url):
    if "." in url and " " not in url and len(url) > 3:
        return True
    
    return False


def request_new_scan(url):
    """Submit a URL to VirusTotal for a fresh analysis"""
    if not VT_API_KEY: return None

    api_url = "https://www.virustotal.com/api/v3/urls"

    payload = {"url": url}
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    response = requests.post(api_url, data=payload, headers=headers)

    if response.status_code == 200:
        return response.json()
    
    return None


def save_log(url, summary_status):
    """Save scan results to a local text file with absolute path"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_name = "scan_history.txt"
    log_entry = f"[{current_time}] URL: {url} | Result: {summary_status}\n"
    
    with open(file_name, "a", encoding="utf-8") as file:
        file.write(log_entry)
    
    abs_path = os.path.abspath(file_name)
    console.print(f"[dim]Log saved to: {abs_path}[/dim]")


def check_google_safe_browsing(url):
    """Query Google Safe Browsing API for URL threats"""
    key = GSB_API_KEY.strip() if GSB_API_KEY else None

    if not key:
        return {"status": "Disabled", "details": ["Key missing"]}
    
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"

    payload = {
        "client": {"clientId": "my-security-tool", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, json=payload, timeout=10)

        if response.status_code != 200:
            return {"status": "Error", "details": [f"HTTP {response.status_code}"]}
        data = response.json()
        if "matches" in data:
            threats = [match["threatType"] for match in data["matches"]]
            return {"status": "Malicious", "details": threats}
        
        return {"status": "Clean", "details": []}
    
    except Exception as e:
        return {"status": "Error", "details": [str(e)]}

def display_unified_report(all_results, url, risk_percentage):
    """Display a unified table of all security providers and a visual risk gauge."""

    # 1. Kaynak Tablosu (Provider Table)
    table = Table(
        title=f"\n[bold white on black] Summary: [/bold white on black] [bold white on red] {url} [/bold white on red] ", 
        box=None,
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("Provider", style="cyan", width=25)
    table.add_column("Verdict", justify="center", width=20)
    table.add_column("Details", style="white")

    for provider, res in all_results.items():
        status = res.get('status', 'N/A')
        details_list = res.get('details', [])
        
        if status == "Malicious":
            verdict = "[red]🚨 MALICIOUS[/red]"
            details = ", ".join(details_list) if details_list else "Threat Detected"
        elif status == "Clean":
            verdict = "[green]✅ CLEAN[/green]"
            details = "[dim]No threats found[/dim]"
        elif status == "Error":
            verdict = "[yellow]⚠️ ERROR[/yellow]"
            details = f"[italic]{', '.join(details_list)}[/italic]"
        else:
            verdict = "[dim]N/A[/dim]"
            details = "[dim]Provider not active or no data[/dim]"
        
        table.add_row(provider, verdict, details)

    console.print(table)

    if risk_percentage < 20:
        color = "green"
        status_text = "LOW RISK"
    elif risk_percentage < 60:
        color = "yellow"
        status_text = "MEDIUM RISK"
    else:
        color = "red"
        status_text = "HIGH RISK"

    filled_blocks = int(risk_percentage // 5)
    empty_blocks = 20 - filled_blocks
    bar = f"[{color}]{'█' * filled_blocks}{'░' * empty_blocks}[/{color}]"

    risk_panel = Panel(
        f"[bold {color}]{status_text} (%{risk_percentage})[/bold {color}]\n"
        f"{bar}\n\n"
        f"[dim]Note: This score is an automated calculation based on security APIs.\n For best results, integrate both APIs [/dim]",
        title="[bold]Risk Assessment[/bold]",
        border_style=color,
        padding=(1, 2),
        expand=False
    )
    
    console.print(risk_panel)
    console.print("\n" + "—" * 60 + "\n")
    

def calculate_risk_score(vt_stats, gsb_res):

    stats = vt_stats if isinstance(vt_stats, dict) else {}
    gsb = gsb_res if isinstance(gsb_res, dict) else {}

    if gsb.get('status') == "Malicious":
        return 100

    score = 0
    malicious_count = stats.get('malicious', 0)
    suspicious_count = stats.get('suspicious', 0)

    if malicious_count >= 5:
        return 100
    elif malicious_count == 4:
        score += 85
    elif malicious_count == 3:
        score += 65
    elif malicious_count == 2:
        score += 40
    elif malicious_count == 1:
        score += 20 

    if suspicious_count > 0:
        score += min(suspicious_count * 5, 15)

    return min(int(score), 100)

# --- MAIN CONTROLLER ---
def main():
    """Main execution flow of the program"""

    # Run setup check
    if not check_setup():
        return
    
    scan_count = 0
    malicious_found = 0

    while True:
        console.print ("\n" + "="*60)
        get_target_url = Prompt.ask("[bold yellow]Enter URL to scan (or 'q' to quit)[/bold yellow]")
    
        if get_target_url.lower() == 'q':
            summary = f"Total Scans in this Session: {scan_count}\nMalicious Detected: {malicious_found}"
            console.print(Panel(summary, title="[bold]Session Summary[/bold]", border_style="cyan"))
            console.print("[bold cyan]Exiting... Stay safe![/bold cyan]")
            break

        if not is_valid_url (get_target_url):
            console.print("[bold red]ERROR:[/bold red] Please enter a valid domain or URL (e.g., example.com).")
            continue
        

        unified_data = {}
        final_verdict = "Clean"
        vt_stats = {}
        gsb_res = {}
        risk_pct = 0

        if VT_API_KEY:
            encoded_url = encode_url(get_target_url)

            with console.status("[bold cyan]Querying VirusTotal...[/bold cyan]"):
                report_data = fetch_vt_report(encoded_url)

            if report_data == "NEW_URL":
                console.print("[yellow]Notice: This URL is new to VirusTotal. Detailed stats skipped.[/yellow]")
                confirm = Prompt.ask("Submit this URL for a fresh scan? (y/n)", choices=["y", "n"], default="y")
                
                if confirm == "y":
                    with console.status("[bold magenta]Submitting for analysis...[/bold magenta]"):
                        scan_res = request_new_scan(get_target_url)
                        if scan_res:
                            console.print("[bold green]SUCCESS:[/bold green] URL submitted. Please wait 1-2 minutes and try again.")
                        else:
                            console.print("[bold red]ERROR:[/bold red] Submission failed.")

                unified_data ["VirusTotal"] = {"status": "Clean", "details": ["Scanning Requested"]}

            elif report_data:
                vt_stats, vt_flagged = parse_vt_results(report_data)
                display_vt_report(vt_stats, vt_flagged, get_target_url)
                
                
                status = "Malicious" if vt_stats.get('malicious', 0) > 0 else "Clean"
                unified_data["VirusTotal"] = {
                    "status": status,
                    "details": [f"{e['engine']}" for e in vt_flagged]
                }
                if status == "Malicious":
                    final_verdict = "Malicious"

        
        if GSB_API_KEY:
            with console.status("[bold magenta]Querying Google Safe Browsing...[/bold magenta]"):
                gsb_res = check_google_safe_browsing(get_target_url)
                unified_data["Google"] = gsb_res
                if gsb_res.get('status') == "Malicious":
                    final_verdict = "Malicious"
        scan_count += 1
        if final_verdict == "Malicious":
            malicious_found +=1

        risk_pct = calculate_risk_score(vt_stats, gsb_res)
        display_unified_report(unified_data, get_target_url, risk_pct)


        save_log(get_target_url, final_verdict)


if __name__ == "__main__":
    main()
