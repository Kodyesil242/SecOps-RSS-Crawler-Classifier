import feedparser
from bs4 import BeautifulSoup
import re
import time
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich.live import Live

console = Console()

class SecOpsCrawler:
    def __init__(self):
        self.rss_sources = [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.exploit-db.com/rss.xml",
            "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
            "https://www.schneier.com/blog/atom.xml"
        ]
        
        self.categories = {
            "Network": ["tcp", "ip", "ddos", "router", "firewall", "port"],
            "Web": ["xss", "sql injection", "csrf", "wordpress", "php", "html"],
            "Crypto": ["bitcoin", "blockchain", "ransomware", "encryption"],
            "System": ["kernel", "linux", "windows", "privilege escalation"]
        }

    def clean_html(self, html_content):
        soup = BeautifulSoup(html_content, "html.parser")
        return soup.get_text()

    def calculate_score(self, title, summary):
        score = 0
        text = (title + " " + summary).lower()
        critical_keywords = {"rce": 35, "zero-day": 40, "critical": 20, "exploit": 15}
        for word, pts in critical_keywords.items():
            if word in text: score += pts
        if re.search(r'cve-\d{4}-\d+', text): score += 25
        return min(score, 100)

    def fetch_data(self):
        all_news = []
        for url in self.rss_sources:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:8]:
                    title = entry.title
                    summary = self.clean_html(entry.get('summary', ''))
                    score = self.calculate_score(title, summary)
                    all_news.append({
                        "title": title[:70] + "...",
                        "score": str(score),
                        "source": feed.feed.get('title', 'Kaynak')[:15]
                    })
            except: pass
        return sorted(all_news, key=lambda x: int(x['score']), reverse=True)[:12]

def show_banner():
    banner = """
    [bold green]
    ███████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
    ██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
    ███████╗█████╗  ██║     ██║   ██║██████╔╝███████╗
    ╚════██║██╔══╝  ██║     ██║   ██║██╔═══╝ ╚════██║
    ███████║███████╗╚██████╗╚██████╔╝██║     ███████║
    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
    [/bold green]
    [bold cyan]CRAWLER & CLASSIFIER SYSTEM - VER: 2.0[/bold cyan]
    [bold yellow]DEVELOPER: MEHMET KEREM BIYIK[/bold yellow]
    """
    console.print(Panel(banner, border_style="green"))

def run_system():
    os.system('cls' if os.name == 'nt' else 'clear')
    show_banner()
    crawler = SecOpsCrawler()
    
    try:
        while True:
            # Tarama animasyonu
            for _ in track(range(10), description="[green]Siber İstihbarat Toplanıyor..."):
                time.sleep(0.1)
            
            data = crawler.fetch_data()
            
            table = Table(title=f"Siber Tehdit Raporu - {datetime.now().strftime('%H:%M:%S')}", border_style="green")
            table.add_column("SKOR", style="bold red", justify="center")
            table.add_column("HABER BAŞLIĞI", style="green")
            table.add_column("KAYNAK", style="cyan")

            for item in data:
                table.add_row(item['score'], item['title'], item['source'])
            
            console.print(table)
            console.print("\n[dim green]3 saniye içinde yeni tarama yapılacak... (Durdurmak için Ctrl+C)[/dim green]")
            time.sleep(3)
            os.system('cls' if os.name == 'nt' else 'clear')
            show_banner()
            
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Sistem Kapatıldı.[/bold red]")

if __name__ == "__main__":
    run_system()