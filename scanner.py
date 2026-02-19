import argparse
import os
import sys
from urllib.parse import urljoin
import asyncio
import httpx

class WebScanner:
    def __init__(self, url, wordlist_path, webhook_url=None, max_retry=3, threads=5):
        self.url = url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.webhook_url = webhook_url
        self.max_retry = max_retry
        self.threads = threads
        self.client = httpx.AsyncClient(
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            },
            timeout=10.0
        )
        self.index_content = None
        self.not_found_content = None
        self.load_wordlist()

    def load_wordlist(self):
        try:
            if not os.path.exists(self.wordlist_path):
                print(f"Wordlist file '{self.wordlist_path}' not found. Using default wordlist.")
                self.wordlist = [
                    'admin', 'login', 'config', 'backup', 'test', 'phpinfo.php', '.env', '.git', 'wp-admin', 'wp-login.php'
                ]
            else:
                with open(self.wordlist_path, 'r') as f:
                    self.wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading wordlist: {e}. Using default wordlist.")
            self.wordlist = [
                'admin', 'login', 'config', 'backup', 'test', 'phpinfo.php', '.env', '.git', 'wp-admin', 'wp-login.php'
            ]

    async def get_page_content(self, path=''):
        full_url = urljoin(self.url, path)
        for attempt in range(self.max_retry + 1):
            try:
                response = await self.client.get(full_url)
                return response.status_code, response.text.lower()
            except httpx.RequestError as e:
                if attempt < self.max_retry:
                    print(f"Attempt {attempt + 1} failed for {full_url}: {e}. Retrying...")
                else:
                    print(f"Error requesting {full_url} after {self.max_retry} retries: {e}")
                    return None, None

    async def detect_index_and_404(self):
        status, content = await self.get_page_content('')
        if status == 200:
            self.index_content = content
        else:
            print("Failed to get index page.")
            return False

        status, content = await self.get_page_content('nonexistentpage12345')
        if status == 404:
            self.not_found_content = content
        else:
            status, content = await self.get_page_content('anothernonexistent98765')
            if status == 404:
                self.not_found_content = content
            else:
                print("Unable to detect 404 page. Proceeding with caution.")
                self.not_found_content = None

        return True

    def is_similar_to_index_or_404(self, content):
        if self.index_content and self.similarity(content, self.index_content) > 0.8:
            return True
        if self.not_found_content and self.similarity(content, self.not_found_content) > 0.8:
            return True
        return False

    def similarity(self, text1, text2):
        words1 = set(text1.split())
        words2 = set(text2.split())
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        return len(intersection) / len(union) if union else 0

    async def check_path(self, path, found_paths):
        try:
            full_url = urljoin(self.url, path)
            status, content = await self.get_page_content(path)
            if status and 200 <= status < 300:
                if not self.is_similar_to_index_or_404(content):
                    print(f"Found: {full_url} (Status: {status})")
                    found_paths.append(full_url)
                    if self.webhook_url:
                        await self.send_discord_webhook(full_url, status)
                else:
                    print(f"Skipped (similar to index/404): {full_url}")
            elif status:
                print(f"Not found: {full_url} (Status: {status})")
        except Exception as e:
            print(f"Error checking path {path}: {e}")

    async def scan(self):
        try:
            if not await self.detect_index_and_404():
                return

            found_paths = []
            semaphore = asyncio.Semaphore(self.threads)
            async def limited_check(path):
                async with semaphore:
                    try:
                        await self.check_path(path, found_paths)
                    except Exception as e:
                        print(f"Error in limited_check for {path}: {e}")

            tasks = [limited_check(path) for path in self.wordlist]
            await asyncio.gather(*tasks)

            if found_paths:
                print(f"\nTotal found: {len(found_paths)}")
            else:
                print("\nNo sensitive files found.")
        except Exception as e:
            print(f"Error during scan: {e}")

    async def send_discord_webhook(self, url, status):
        if not self.webhook_url:
            return
        payload = {
            "embeds": [{
                "title": "Sensitive File Found",
                "description": f"URL: {url}\nStatus: {status}",
                "color": 16711680
            }]
        }
        try:
            response = await self.client.post(self.webhook_url, json=payload)
            if response.status_code == 204:
                print("Webhook sent successfully.")
            else:
                print(f"Failed to send webhook: {response.status_code}")
        except httpx.RequestError as e:
            print(f"Error sending webhook: {e}")

def main():
    try:
        parser = argparse.ArgumentParser(description="Web Directory/File Scanner")
        parser.add_argument('--url', required=True, help='Target URL to scan')
        parser.add_argument('--wordlist', default='wl.txt', help='Path to wordlist file (default: wl.txt)')
        parser.add_argument('--webhook', help='Discord webhook URL for notifications')
        parser.add_argument('--max-retry', type=int, default=3, help='Maximum number of retries on error (default: 3)')
        parser.add_argument('--thread', type=int, default=5, help='Number of concurrent threads (default: 5)')

        args = parser.parse_args()

        scanner = WebScanner(args.url, args.wordlist, args.webhook, args.max_retry, args.thread)
        asyncio.run(scanner.scan())
    except Exception as e:
        print(f"Error in main: {e}")

if __name__ == "__main__":
    main()
