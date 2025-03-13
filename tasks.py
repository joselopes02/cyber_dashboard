# tasks.py
import os
import json
from celery_app import celery
from flask import current_app, render_template
from statistics_helpers import (
    get_total_counts,
    get_dataset_duration,
    get_daily_time_series,
    get_top_domains,
    get_top_payloads,
    get_pie_chart_data,
    get_location_data,
    get_top_threat_tokens,
    get_top_popular_labelcounts
)

@celery.task
def generate_static_statistics():
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
    with current_app.test_request_context():
	    rendered_html = render_template("statistics.html",
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
    static_folder = current_app.static_folder
    file_path = os.path.join(static_folder, "statistics.html")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)
    print("Static statistics page updated.")
