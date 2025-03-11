from flask import Blueprint, render_template
from models import URL, Download

statistics_bp = Blueprint('statistics', __name__, url_prefix='/statistics')

@statistics_bp.route('/')
def statistics():
    try:
        # Example metric: total number of URL records
        total_urls = URL.query.count()
        # Example metric: count of downloads with a malicious flag (greater than 0)
        malicious_downloads = Download.query.filter(Download.malicious_flags > 0).count()
        total_downloads = Download.query.count()
        # Calculate a simple ratio metric
        ratio = total_urls / total_downloads if total_downloads > 0 else None
        
        # Additional metrics can be added here
        stats = {
            'total_urls': total_urls,
            'total_downloads': total_downloads,
            'malicious_downloads': malicious_downloads,
            'url_to_download_ratio': ratio,
        }
    except Exception as e:
        return render_template('error.html', message=str(e)), 500

    return render_template('statistics.html', stats=stats)
