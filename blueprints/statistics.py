from flask import Blueprint, render_template
from models import URL, Download, Attack, db
from sqlalchemy import func
from datetime import datetime
import json
from extensions import cache
from urllib.parse import urlparse
from collections import Counter

statistics_bp = Blueprint('statistics', __name__, url_prefix='/statistics')

def extract_domain(url):
    # Prepend scheme if missing, then parse hostname
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.hostname

@cache.memoize(timeout=600)
def get_total_counts():
    url_count = URL.query.count()
    attack_url_count = Attack.query.filter(Attack.url != None, Attack.url != '').count()
    attack_md5_count = Attack.query.filter(Attack.md5 != None, Attack.md5 != '').count()
    download_count = Download.query.count()
    return url_count, attack_url_count, attack_md5_count, download_count

@cache.memoize(timeout=600)
def get_dataset_duration():
    valid_date = (Attack.date != None, Attack.date != '')
    min_date_str = db.session.query(func.min(Attack.date)).filter(*valid_date).scalar()
    max_date_str = db.session.query(func.max(Attack.date)).filter(*valid_date).scalar()
    if min_date_str and max_date_str:
        try:
            min_date = datetime.strptime(min_date_str.strip()[:10], "%Y-%m-%d").date()
            max_date = datetime.strptime(max_date_str.strip()[:10], "%Y-%m-%d").date()
            days = (max_date - min_date).days + 1
        except Exception:
            days = 1
    else:
        days = 1
    return days

@cache.memoize(timeout=600)
def get_daily_time_series():
    valid_date = (Attack.date != None, Attack.date != '')
    valid_url  = (Attack.url != None, Attack.url != '')
    valid_md5  = (Attack.md5 != None, Attack.md5 != '')
    # Daily distinct URLs
    daily_urls = db.session.query(
        func.substr(Attack.date, 1, 10).label("day"),
        func.count(func.distinct(Attack.url)).label("url_count")
    ).filter(*valid_date, *valid_url).group_by("day").order_by("day").all()
    # Daily distinct Payloads
    daily_payloads = db.session.query(
        func.substr(Attack.date, 1, 10).label("day"),
        func.count(func.distinct(Attack.md5)).label("payload_count")
    ).filter(*valid_date, *valid_md5).group_by("day").order_by("day").all()
    
    daily_url_labels = [row.day for row in daily_urls]
    daily_url_counts = [row.url_count for row in daily_urls]
    daily_payload_labels = [row.day for row in daily_payloads]
    daily_payload_counts = [row.payload_count for row in daily_payloads]
    # Build combined series using union of days
    all_days = sorted(set(daily_url_labels) | set(daily_payload_labels))
    url_dict = {row.day: row.url_count for row in daily_urls}
    payload_dict = {row.day: row.payload_count for row in daily_payloads}
    combined_total = [url_dict.get(day, 0) + payload_dict.get(day, 0) for day in all_days]
    
    return daily_url_labels, daily_url_counts, daily_payload_labels, daily_payload_counts, all_days, combined_total

@cache.memoize(timeout=600)
def get_top_domains():
    valid_url = (Attack.url != None, Attack.url != '')
    attack_urls = db.session.query(Attack.url).filter(*valid_url).all()
    domain_counts = {}
    for (url_val,) in attack_urls:
        try:
            domain = extract_domain(url_val)
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
        except Exception:
            continue
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return top_domains

@cache.memoize(timeout=600)
def get_top_payloads():
    valid_md5 = (Attack.md5 != None, Attack.md5 != '')
    attack_md5s = db.session.query(Attack.md5).filter(*valid_md5).all()
    payload_counts = {}
    for (md5_val,) in attack_md5s:
        token = md5_val.strip()
        if token:
            payload_counts[token] = payload_counts.get(token, 0) + 1
    top_payloads = sorted(payload_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return top_payloads

@cache.memoize(timeout=600)
def get_pie_chart_data():
    # Honeypot Distribution
    honeypot_stats = db.session.query(
        Attack.honeypot_name,
        func.count(Attack.id).label("count")
    ).filter(Attack.honeypot_name != None, Attack.honeypot_name != '').group_by(Attack.honeypot_name).all()
    honeypot_labels = [row.honeypot_name for row in honeypot_stats]
    honeypot_counts = [row.count for row in honeypot_stats]
    
    # Protocol Distribution
    protocol_stats = db.session.query(
        Attack.protocol,
        func.count(Attack.id).label("count")
    ).filter(Attack.protocol != None, Attack.protocol != '').group_by(Attack.protocol).all()
    protocol_labels = [row.protocol for row in protocol_stats]
    protocol_counts = [row.count for row in protocol_stats]
    
    return honeypot_labels, honeypot_counts, protocol_labels, protocol_counts

@cache.memoize(timeout=600)
def get_location_data():
    locations = db.session.query(Attack.latitude, Attack.longitude)\
                    .filter(Attack.latitude != None, Attack.longitude != None)\
                    .all()
    location_data = [{"lat": loc[0], "lng": loc[1]} for loc in locations]
    return location_data

@cache.memoize(timeout=600)
def get_top_threat_tokens():
    urls_with_threats = URL.query.filter(URL.threat_names != None, URL.threat_names != '').all()
    threat_tokens = Counter()
    for url_obj in urls_with_threats:
        tokens = [token.strip().lower() for token in url_obj.threat_names.split(',') if token.strip()]
        threat_tokens.update(tokens)
    return threat_tokens.most_common(10)

@cache.memoize(timeout=600)
def get_top_popular_labelcounts():
    downloads_with_labels = Download.query.filter(Download.popular_label != None, Download.popular_label != '').all()
    popular_labels = Counter()
    for download_obj in downloads_with_labels:
        tokens = [token.strip().lower() for token in download_obj.popular_label.split(',') if token.strip()]
        popular_labels.update(tokens)
    return popular_labels.most_common(10)

@statistics_bp.route('/')
@cache.cached(timeout=600)
def statistics():
    # Retrieve pre-aggregated data from the cache
    url_count, attack_url_count, attack_md5_count, download_count = get_total_counts()
    days = get_dataset_duration()
    
    avg_urls_per_day = url_count / days
    avg_downloads_per_day = download_count / days
    avg_attacks_url_per_day = attack_url_count / days
    avg_attacks_payload_per_day = attack_md5_count / days
    
    (daily_url_labels, daily_url_counts, daily_payload_labels, daily_payload_counts,
     all_days, combined_total) = get_daily_time_series()
    
    top_domains = get_top_domains()
    top_payloads = get_top_payloads()
    honeypot_labels, honeypot_counts, protocol_labels, protocol_counts = get_pie_chart_data()
    location_data = get_location_data()
    top_threat_tokens = get_top_threat_tokens()
    top_popular_labelcounts = get_top_popular_labelcounts()
    
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
