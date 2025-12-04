#!/usr/bin/env python3
"""
CredibilityChecker

Setup:
    pip install requests beautifulsoup4 python-whois

Usage:
    CLI: python credibility_checker.py <url>
    UI:  python credibility_checker.py --ui
    (or run without args to be prompted in CLI)
"""

import datetime
import re
import sys
import threading
import urllib.parse
from collections import Counter

try:
    import requests
    from bs4 import BeautifulSoup
    import whois
except ImportError as exc:
    print(f"Missing dependency: {exc}. Install with 'pip install requests beautifulsoup4 python-whois'.")
    sys.exit(1)


HEADERS = {
    "User-Agent": "Mozilla/5.0 (CredibilityChecker)",
    "Accept-Language": "en-US,en;q=0.9",
}

REPUTABLE_DOMAINS = {
    "wikipedia.org",
    "nytimes.com",
    "bbc.com",
    "reuters.com",
    "apnews.com",
    "theguardian.com",
    "npr.org",
    "nature.com",
    "science.org",
    "nasa.gov",
    "nih.gov",
}


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        return raw_url
    if not re.match(r"^https?://", raw_url, flags=re.IGNORECASE):
        return f"http://{raw_url}"
    return raw_url


def extract_domain(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    return host.split(":")[0]  # drop port


def fetch_page(url: str) -> BeautifulSoup | None:
    try:
        response = requests.get(url, headers=HEADERS, timeout=12)
        response.raise_for_status()
        return BeautifulSoup(response.text, "html.parser")
    except Exception as exc:
        print(f"Could not fetch page: {exc}")
        return None


def get_domain_age_years(domain: str) -> float | None:
    try:
        info = whois.whois(domain)
    except Exception:
        return None

    creation_date = info.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if not creation_date:
        return None
    if isinstance(creation_date, datetime.date) and not isinstance(creation_date, datetime.datetime):
        creation_date = datetime.datetime.combine(creation_date, datetime.datetime.min.time())

    try:
        delta = datetime.datetime.utcnow() - creation_date.replace(tzinfo=None)
        return delta.days / 365.25
    except Exception:
        return None


def has_author_info(soup: BeautifulSoup) -> bool:
    meta_author = soup.find("meta", attrs={"name": "author"})
    if meta_author and meta_author.get("content"):
        return True
    author_like = soup.find(attrs={"rel": re.compile("author", re.I)}) or soup.find(
        class_=re.compile("author|byline", re.I)
    )
    return bool(author_like)


def has_publication_date(soup: BeautifulSoup) -> bool:
    date_meta_names = [
        "article:published_time",
        "date",
        "dc.date",
        "dc.date.issued",
        "pubdate",
        "publication_date",
    ]
    for name in date_meta_names:
        if soup.find("meta", attrs={"name": name}) or soup.find("meta", attrs={"property": name}):
            return True

    time_tag = soup.find("time", attrs={"datetime": True}) or soup.find("time")
    if time_tag and (time_tag.get("datetime") or time_tag.text):
        return True
    return False


def has_citations(soup: BeautifulSoup, domain: str) -> bool:
    external_credible = 0
    for link in soup.find_all("a", href=True):
        href = link["href"]
        if href.startswith("#") or href.lower().startswith("mailto:"):
            continue
        parsed = urllib.parse.urlparse(href)
        if not parsed.netloc:
            continue
        host = parsed.netloc.lower().split(":")[0]
        if host == domain or host.endswith("." + domain):
            continue
        if host.endswith(".gov") or host.endswith(".edu"):
            external_credible += 1
        elif any(rep in host for rep in ("wikipedia.org", "reuters.com", "apnews.com", "bbc.com", "nytimes.com")):
            external_credible += 1
    return external_credible >= 2


def detect_ads(soup: BeautifulSoup) -> bool:
    ad_like = soup.find_all(attrs={"class": re.compile("ad|ads|advert", re.I)})
    ad_like += soup.find_all(attrs={"id": re.compile("ad|ads|advert", re.I)})
    iframes = soup.find_all("iframe")
    scripts = soup.find_all("script", src=re.compile("ads|doubleclick|googlesyndication", re.I))
    return len(ad_like) + len(iframes) + len(scripts) >= 8


def detect_keyword_spam(text: str) -> bool:
    words = re.findall(r"[a-zA-Z]{3,}", text.lower())
    if len(words) < 50:
        return False
    counts = Counter(words)
    most_common, freq = counts.most_common(1)[0]
    return freq / len(words) > 0.12 and freq > 20


def domain_on_reputable_list(domain: str) -> bool:
    return any(domain == rep or domain.endswith("." + rep) for rep in REPUTABLE_DOMAINS)


def evaluate_credibility(url: str) -> dict:
    normalized_url = normalize_url(url)
    domain = extract_domain(normalized_url)
    soup = fetch_page(normalized_url)
    text_content = soup.get_text(" ", strip=True) if soup else ""

    score = 0
    strengths: list[str] = []
    weaknesses: list[str] = []

    if domain.endswith(".edu") or domain.endswith(".gov"):
        score += 20
        strengths.append("Trusted domain (.edu/.gov)")

    age_years = get_domain_age_years(domain)
    if age_years is not None and age_years >= 5:
        score += 10
        strengths.append(f"Domain age > 5 years (~{age_years:.1f} yrs)")
    else:
        score -= 10
        weaknesses.append("Domain is new or age unknown")

    if normalized_url.startswith("https://"):
        score += 10
        strengths.append("HTTPS enabled")
    else:
        weaknesses.append("Not using HTTPS")

    if soup:
        if has_author_info(soup):
            score += 10
            strengths.append("Author info found")
        else:
            weaknesses.append("No author information detected")

        if has_publication_date(soup):
            score += 10
            strengths.append("Publication date found")
        else:
            weaknesses.append("No publication date detected")

        if has_citations(soup, domain):
            score += 10
            strengths.append("References/citations detected")
        else:
            weaknesses.append("No citations detected")

        if detect_ads(soup):
            score -= 15
            weaknesses.append("Many ads present")

        if detect_keyword_spam(text_content):
            score -= 10
            weaknesses.append("Keyword stuffing detected")

        if domain_on_reputable_list(domain):
            strengths.append("Recognized reputable domain")
    else:
        weaknesses.append("Page could not be fetched for analysis")

    score = max(0, min(100, score))

    if score >= 70:
        verdict = "Credible"
    elif score >= 40:
        verdict = "Mixed"
    else:
        verdict = "Not Credible"

    return {
        "url": normalized_url,
        "score": score,
        "strengths": strengths,
        "weaknesses": weaknesses,
        "verdict": verdict,
    }


def print_report(result: dict) -> None:
    print(f"URL: {result['url']}")
    print(f"Score: {result['score']}/100")
    if result["strengths"]:
        print("Strengths: " + ", ".join(result["strengths"]))
    else:
        print("Strengths: None detected")
    if result["weaknesses"]:
        print("Weaknesses: " + ", ".join(result["weaknesses"]))
    else:
        print("Weaknesses: None detected")
    print(f"Final verdict: {result['verdict']}")


def start_ui() -> None:
    try:
        import tkinter as tk
        from tkinter import messagebox, scrolledtext
    except Exception as exc:
        print(f"Tkinter UI unavailable: {exc}")
        sys.exit(1)

    root = tk.Tk()
    root.title("CredibilityChecker")

    url_var = tk.StringVar()

    def render_report(report: dict) -> None:
        lines = [
            f"URL: {report['url']}",
            f"Score: {report['score']}/100",
            "Strengths: " + (", ".join(report["strengths"]) if report["strengths"] else "None detected"),
            "Weaknesses: " + (", ".join(report["weaknesses"]) if report["weaknesses"] else "None detected"),
            f"Final verdict: {report['verdict']}",
        ]
        output.configure(state="normal")
        output.delete("1.0", tk.END)
        output.insert(tk.END, "\n".join(lines))
        output.configure(state="disabled")

    def run_check() -> None:
        url = url_var.get().strip()
        if not url:
            messagebox.showinfo("Missing URL", "Please enter a URL.")
            return

        output.configure(state="normal")
        output.delete("1.0", tk.END)
        output.insert(tk.END, "Checking...\n")
        output.configure(state="disabled")
        check_btn.configure(state="disabled")

        def worker() -> None:
            try:
                report = evaluate_credibility(url)
                root.after(0, lambda: render_report(report))
            except Exception as exc:
                root.after(0, lambda: messagebox.showerror("Error", f"Could not evaluate: {exc}"))
            finally:
                root.after(0, lambda: check_btn.configure(state="normal"))

        threading.Thread(target=worker, daemon=True).start()

    container = tk.Frame(root, padx=10, pady=10)
    container.pack(fill="both", expand=True)

    tk.Label(container, text="Enter URL:").grid(row=0, column=0, sticky="w")
    url_entry = tk.Entry(container, textvariable=url_var, width=50)
    url_entry.grid(row=0, column=1, padx=(5, 0), pady=(0, 8), sticky="we")
    check_btn = tk.Button(container, text="Check", command=run_check)
    check_btn.grid(row=0, column=2, padx=(8, 0))

    output = scrolledtext.ScrolledText(container, width=70, height=12, state="disabled", wrap="word")
    output.grid(row=1, column=0, columnspan=3, pady=(6, 0), sticky="nsew")

    container.columnconfigure(1, weight=1)
    container.rowconfigure(1, weight=1)
    url_entry.focus()

    root.mainloop()


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--ui":
        try:
            start_ui()
        except Exception as exc:
            print(f"UI failed to start: {exc}")
        return

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter a URL to check: ").strip()

    if not url:
        print("No URL provided.")
        return

    try:
        report = evaluate_credibility(url)
        print_report(report)
    except Exception as exc:
        print(f"Something went wrong while evaluating credibility: {exc}")


if __name__ == "__main__":
    main()
