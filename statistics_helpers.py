from .models import URL, Download, Attack, Augmented_Attacks, db
from sqlalchemy import func
from datetime import datetime
import json
from .extensions import cache
from urllib.parse import urlparse
from collections import Counter

def get_attacks_union():
    attack_query = db.session.query(
        Attack.id.label("id"),
        Attack.date.label("date"),
        Attack.source_ip.label("source_ip"),
        Attack.source_port.label("source_port"),
        Attack.url.label("url"),
        Attack.protocol.label("protocol"),
        Attack.honeypot_name.label("honeypot_name"),
        Attack.md5.label("md5"),
        Attack.honeypot_ip.label("honeypot_ip"),
        Attack.honeypot_service.label("honeypot_service"),
        Attack.city.label("city"),
        Attack.country_name.label("country_name"),
        Attack.continent.label("continent"),
        Attack.org.label("org"),
        Attack.latitude.label("latitude"),
        Attack.longitude.label("longitude")
    )
    augmented_query = db.session.query(
        Augmented_Attacks.id.label("id"),
        Augmented_Attacks.date.label("date"),
        Augmented_Attacks.source_ip.label("source_ip"),
        Augmented_Attacks.source_port.label("source_port"),
        Augmented_Attacks.url.label("url"),
        Augmented_Attacks.protocol.label("protocol"),
        Augmented_Attacks.honeypot_name.label("honeypot_name"),
        Augmented_Attacks.md5.label("md5"),
        Augmented_Attacks.honeypot_ip.label("honeypot_ip"),
        Augmented_Attacks.honeypot_service.label("honeypot_service"),
        Augmented_Attacks.city.label("city"),
        Augmented_Attacks.country_name.label("country_name"),
        Augmented_Attacks.continent.label("continent"),
        Augmented_Attacks.org.label("org"),
        Augmented_Attacks.latitude.label("latitude"),
        Augmented_Attacks.longitude.label("longitude")
    )
    # Use union_all to combine both queries.
    return attack_query.union_all(augmented_query).subquery()


def extract_domain(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return urlparse(url).hostname


@cache.memoize(timeout=600)
def get_total_counts():
    attacks_union = get_attacks_union()
    url_count = URL.query.count()
    attack_url_count = db.session.query(attacks_union)\
        .filter(attacks_union.c.url != None, attacks_union.c.url != '').count()
    attack_md5_count = db.session.query(attacks_union)\
        .filter(attacks_union.c.md5 != None, attacks_union.c.md5 != '').count()
    download_count = Download.query.count()
    return url_count, attack_url_count, attack_md5_count, download_count


@cache.memoize(timeout=600)
def get_dataset_duration():
    attacks_union = get_attacks_union()
    valid_date = (attacks_union.c.date != None, attacks_union.c.date != '')
    min_date_str = db.session.query(func.min(attacks_union.c.date)).filter(*valid_date).scalar()
    max_date_str = db.session.query(func.max(attacks_union.c.date)).filter(*valid_date).scalar()
    if min_date_str and max_date_str:
        try:
            min_date = datetime.strptime(min_date_str.strip()[:10], "%Y-%m-%d").date()
            max_date = datetime.strptime(max_date_str.strip()[:10], "%Y-%m-%d").date()
            days = (max_date - min_date).days + 1
        except Exception:
            days = 1
    else:
        days = 1
    return (days - 18)


@cache.memoize(timeout=600)
def get_daily_time_series():
    attacks_union = get_attacks_union()
    valid_date = (attacks_union.c.date != None, attacks_union.c.date != '')
    valid_url  = (attacks_union.c.url != None, attacks_union.c.url != '')
    valid_md5  = (attacks_union.c.md5 != None, attacks_union.c.md5 != '')
    
    daily_urls = db.session.query(
        func.substr(attacks_union.c.date, 1, 10).label("day"),
        func.count(func.distinct(attacks_union.c.url)).label("url_count")
    ).filter(*valid_date, *valid_url).group_by("day").order_by("day").all()
    
    daily_payloads = db.session.query(
        func.substr(attacks_union.c.date, 1, 10).label("day"),
        func.count(func.distinct(attacks_union.c.md5)).label("payload_count")
    ).filter(*valid_date, *valid_md5).group_by("day").order_by("day").all()

    daily_url_labels = [row.day for row in daily_urls]
    daily_url_counts = [row.url_count for row in daily_urls]
    daily_payload_labels = [row.day for row in daily_payloads]
    daily_payload_counts = [row.payload_count for row in daily_payloads]
    all_days = sorted(set(daily_url_labels) | set(daily_payload_labels))
    url_dict = {row.day: row.url_count for row in daily_urls}
    payload_dict = {row.day: row.payload_count for row in daily_payloads}
    combined_total = [url_dict.get(day, 0) + payload_dict.get(day, 0) for day in all_days]
    return daily_url_labels, daily_url_counts, daily_payload_labels, daily_payload_counts, all_days, combined_total


@cache.memoize(timeout=600)
def get_top_domains():
    attacks_union = get_attacks_union()
    valid_url = (attacks_union.c.url != None, attacks_union.c.url != '')
    attack_urls = db.session.query(attacks_union.c.url).filter(*valid_url).all()
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
    attacks_union = get_attacks_union()
    valid_md5 = (attacks_union.c.md5 != None, attacks_union.c.md5 != '')
    attack_md5s = db.session.query(attacks_union.c.md5).filter(*valid_md5).all()
    payload_counts = {}
    for (md5_val,) in attack_md5s:
        token = md5_val.strip()
        if token:
            payload_counts[token] = payload_counts.get(token, 0) + 1
    top_payloads = sorted(payload_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return top_payloads


@cache.memoize(timeout=600)
def get_pie_chart_data():
    attacks_union = get_attacks_union()
    honeypot_stats = db.session.query(
        attacks_union.c.honeypot_name,
        func.count(attacks_union.c.id).label("count")
    ).filter(attacks_union.c.honeypot_name != None, attacks_union.c.honeypot_name != '')\
     .group_by(attacks_union.c.honeypot_name).all()
    honeypot_labels = [row.honeypot_name for row in honeypot_stats]
    honeypot_counts = [row.count for row in honeypot_stats]
    
    protocol_stats = db.session.query(
        attacks_union.c.protocol,
        func.count(attacks_union.c.id).label("count")
    ).filter(attacks_union.c.protocol != None, attacks_union.c.protocol != '')\
     .group_by(attacks_union.c.protocol).all()
    protocol_labels = [row.protocol for row in protocol_stats]
    protocol_counts = [row.count for row in protocol_stats]
    return honeypot_labels, honeypot_counts, protocol_labels, protocol_counts


@cache.memoize(timeout=600)
def get_location_data():
    attacks_union = get_attacks_union()
    locations = db.session.query(attacks_union.c.latitude, attacks_union.c.longitude)\
                    .filter(attacks_union.c.latitude != None, attacks_union.c.longitude != None)\
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
