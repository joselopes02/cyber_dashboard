from flask import Blueprint, render_template
from models import URL, Download, Attack, db
from sqlalchemy import func
from datetime import datetime
import json
from urllib.parse import urlparse


statistics_bp = Blueprint('statistics', __name__, url_prefix='/statistics')
def extract_domain(url):
    # If the URL doesn't start with a scheme, prepend "http://"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.hostname

@statistics_bp.route('/')
def statistics():
    # Total counts
    url_count = URL.query.count()
    attack_url_count = Attack.query.filter(Attack.url != None, Attack.url != '').count()
    attack_md5_count = Attack.query.filter(Attack.md5 != None, Attack.md5 != '').count()
    download_count = Download.query.count()
    
    # Determine dataset duration using only rows with valid dates.
    min_date_str = db.session.query(func.min(Attack.date)).filter(Attack.date != None, Attack.date != '').scalar()
    max_date_str = db.session.query(func.max(Attack.date)).filter(Attack.date != None, Attack.date != '').scalar()
    print("min",min_date_str)
    print("max",max_date_str)
    
    if min_date_str and max_date_str:
        try:
            min_date = datetime.strptime(min_date_str.strip()[:10], "%Y-%m-%d").date()
            max_date = datetime.strptime(max_date_str.strip()[:10], "%Y-%m-%d").date()
            days = (max_date - min_date).days + 1
            
        except Exception as e:
            days = 1
    else:
        days = 1

    avg_urls_per_day = url_count / days
    avg_downloads_per_day = download_count / days
    avg_attacks_url_per_day = attack_url_count / days
    avg_attacks_payload_per_day = attack_md5_count / days

    # --- Time Series Data for daily distinct counts ---
    # Extract day (YYYY-MM-DD) from Attack.date.
    daily_urls = db.session.query(
        func.substr(Attack.date, 1, 10).label("day"),
        func.count(func.distinct(Attack.url)).label("url_count")
    ).filter(Attack.date != None, Attack.date != '', Attack.url != None, Attack.url != '').group_by("day").order_by("day").all()

    daily_payloads = db.session.query(
        func.substr(Attack.date, 1, 10).label("day"),
        func.count(func.distinct(Attack.md5)).label("payload_count")
    ).filter(Attack.date != None, Attack.date != '', Attack.md5 != None, Attack.md5 != '').group_by("day").order_by("day").all()

    # Convert results to lists.
    daily_url_labels = [row.day for row in daily_urls]
    daily_url_counts = [row.url_count for row in daily_urls]

    daily_payload_labels = [row.day for row in daily_payloads]
    daily_payload_counts = [row.payload_count for row in daily_payloads]

    # Build a combined time series:
    all_days = sorted(set(daily_url_labels) | set(daily_payload_labels))
    url_dict = {row.day: row.url_count for row in daily_urls}
    payload_dict = {row.day: row.payload_count for row in daily_payloads}
    combined_total = [url_dict.get(day, 0) + payload_dict.get(day, 0) for day in all_days]

    # --- Top Domains Board ---
    attacks = Attack.query.filter(Attack.url != None, Attack.url != '').all()
    domain_counts = {}
    for attack in attacks:
        try:
            domain = extract_domain(attack.url)
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
        except Exception:
            continue

    # Sort the domains by count in descending order and take top 10
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # --- Top Payloads Board ---
    attacks_with_md5 = Attack.query.filter(Attack.md5 != None, Attack.md5 != '').all()
    payload_counts = {}
    for attack in attacks_with_md5:
        md5 = attack.md5.strip()
        if md5:
            payload_counts[md5] = payload_counts.get(md5, 0) + 1

    # Sort the payloads by count in descending order and take top 10.
    top_payloads = sorted(payload_counts.items(), key=lambda x: x[1], reverse=True)[:10]

# --- New: Top Honeypot and Protocol Distributions for Pie Charts ---
    honeypot_stats = db.session.query(
        Attack.honeypot_name,
        func.count(Attack.id).label("count")
    ).filter(Attack.honeypot_name != None, Attack.honeypot_name != '').group_by(Attack.honeypot_name).all()
    honeypot_labels = [row.honeypot_name for row in honeypot_stats]
    honeypot_counts = [row.count for row in honeypot_stats]

    protocol_stats = db.session.query(
        Attack.protocol,
        func.count(Attack.id).label("count")
    ).filter(Attack.protocol != None, Attack.protocol != '').group_by(Attack.protocol).all()
    protocol_labels = [row.protocol for row in protocol_stats]
    protocol_counts = [row.count for row in protocol_stats]

    locations = db.session.query(Attack.latitude, Attack.longitude)\
                    .filter(Attack.latitude != None, Attack.longitude != None)\
                    .all()
        
    location_data = [{"lat": loc[0], "lng": loc[1]} for loc in locations]
    
        # --- Top Threat Tokens Board ---
    urls_with_threats = URL.query.filter(URL.threat_names != None, URL.threat_names != '').all()
    threat_token_counts = {}
    for url in urls_with_threats:
        # Split the threat_names string on commas
        tokens = url.threat_names.split(',')
        for token in tokens:
            # Normalize the token by stripping whitespace and converting to lowercase
            normalized = token.strip().lower()
            if normalized:
                threat_token_counts[normalized] = threat_token_counts.get(normalized, 0) + 1

    # Sort the tokens by count in descending order and take the top 10
    top_threat_tokens = sorted(threat_token_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # --- Top popular_label Tokens Board ---
    download_popular_label = Download.query.filter(Download.popular_label != None, Download.popular_label != '').all()
    download_popular_labelcounts = {}
    for download in download_popular_label:
        # Split the popular_label string on commas
        tokens = download.popular_label.split(',')
        for token in tokens:
            # Normalize the token by stripping whitespace and converting to lowercase
            normalized = token.strip().lower()
            if normalized:
                download_popular_labelcounts[normalized] = download_popular_labelcounts.get(normalized, 0) + 1

    # Sort the tokens by count in descending order and take the top 10
    top_popular_labelcounts = sorted(download_popular_labelcounts.items(), key=lambda x: x[1], reverse=True)[:10]


    return render_template("statistics.html",
                           url_count=url_count,
                           attack_url_count=attack_url_count,
                           attack_md5_count=attack_md5_count,
                           download_count=download_count,
                           days=days,
                           avg_urls_per_day=avg_urls_per_day,
                           avg_downloads_per_day=avg_downloads_per_day,
                           avg_attacks_url_per_day=avg_attacks_url_per_day,
                           avg_attacks_payload_per_day=avg_attacks_payload_per_day,
                           daily_url_labels=json.dumps(daily_url_labels),
                           daily_url_counts=json.dumps(daily_url_counts),
                           daily_payload_labels=json.dumps(daily_payload_labels),
                           daily_payload_counts=json.dumps(daily_payload_counts),
                           combined_days=json.dumps(all_days),
                           combined_total=json.dumps(combined_total),
                           top_domains=top_domains,
                           top_payloads=top_payloads,
                           honeypot_labels=json.dumps(honeypot_labels),
                           honeypot_counts=json.dumps(honeypot_counts),
                           protocol_labels=json.dumps(protocol_labels),
                           protocol_counts=json.dumps(protocol_counts),
                           location_data=json.dumps(location_data),
                           top_threat_tokens=top_threat_tokens,
                           top_popular_labelcounts=top_popular_labelcounts
                           )