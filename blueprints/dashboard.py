from flask import Blueprint, render_template, request, abort, send_file, url_for
from models import URL, Download, Attack, db
import io
from extensions import cache

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@dashboard_bp.route('/')
@cache.cached(timeout=180, query_string=True)
def dashboard():
    # Retrieve parameters from the query string
    search_query = request.args.get('search', '')
    view = request.args.get('view', 'links')  
    links_page = int(request.args.get('links_page', 1))
    payload_page = int(request.args.get('payload_page', 1))
    per_page = int(request.args.get('per_page', 20))
    
 
    links_query = db.session.query(
        Attack.date, 
        Attack.url, 
        Attack.protocol, 
        Attack.honeypot_name, 
        URL.threat_names,
        URL.shasum,
        URL.malicious_flags,
        URL.reputation,
        URL.times_submitted
    ).join(URL, Attack.url == URL.url, isouter=True
    ).filter(Attack.url != None, Attack.url != '')
    
    if search_query:
        links_query = links_query.filter(
            (Attack.url.startswith(search_query)) |
            (Attack.protocol.startswith(search_query)) |
            (Attack.honeypot_name.startswith(search_query)) |
            (URL.threat_names.startswith(search_query)) |
            (Attack.date.startswith(search_query)) |
            (URL.shasum.startswith(search_query))
        )
    links_paginated = links_query.paginate(page=links_page, per_page=per_page, error_out=False)
    

    payloads_query = db.session.query(
        Attack.date, 
        Attack.md5, 
        Attack.protocol, 
        Attack.honeypot_name, 
        Download.type, 
        Download.reputation, 
        Download.times_submitted, 
        Download.popular_label, 
        Download.times_submitted, 
        Download.reputation,
        Download.malicious_flags

    ).join(Download, Attack.md5 == Download.md5, isouter=True
    ).filter(Attack.md5 != None, Attack.md5 != '')
    
    if search_query:
            payloads_query = payloads_query.filter(
                (Attack.md5.startswith(search_query)) |
                (Download.type.startswith(search_query)) |
                (Attack.protocol.startswith(search_query)) |
                (Attack.date.startswith(search_query)) |
                (Attack.honeypot_name.startswith(search_query))
            )
        
    payloads_paginated = payloads_query.paginate(page=payload_page, per_page=per_page, error_out=False)
    
    return render_template(
        'dashboard.html',
        view=view,
        links=links_paginated.items,
        payloads=payloads_paginated.items,
        links_paginated=links_paginated,
        payloads_paginated=payloads_paginated,
        search_query=search_query
    )

@dashboard_bp.route('/record/<record_type>/<identifier>')
@cache.cached(timeout=180)
def record_detail(record_type, identifier):
    if record_type == 'link':

        record = db.session.query(
                    Attack.date,
                    Attack.source_ip,
                    Attack.source_port,
                    Attack.url,
                    Attack.protocol,
                    Attack.honeypot_name,
                    Attack.latitude,      
                    Attack.longitude, 
                    URL.threat_names,
                    URL.shasum,
                    URL.malicious_flags,
                    URL.times_submitted,
                    URL.reputation
                ).join(URL, Attack.url == URL.url, isouter=True
                ).filter(URL.shasum == identifier).first_or_404()
        download_record = Download.query.filter_by(sha256=record.shasum).first()
        return render_template('record_detail.html', record=record, record_type=record_type, download_record=download_record)
    elif record_type == 'payload':

        record = db.session.query(
                    Attack.date, 
                    Attack.md5,
                    Attack.source_ip,
                    Attack.source_port, 
                    Attack.protocol, 
                    Attack.honeypot_name,
                    Attack.latitude,      
                    Attack.longitude, 
                    Download.type, 
                    Download.reputation, 
                    Download.times_submitted, 
                    Download.file_size,
                    Download.popular_label, 
                    Download.malicious_flags
                ).join(Download, Attack.md5 == Download.md5, isouter=True
                ).filter(Attack.md5 == identifier).first_or_404()
        return render_template('record_detail.html', record=record, record_type=record_type)
    else:
        abort(404)


@dashboard_bp.route('/download/<md5>')
def download_file(md5):
    record = Download.query.filter_by(md5=md5).first_or_404()
    return send_file(
        io.BytesIO(record.file_data),
        attachment_filename=f"{md5}.zip",
        as_attachment=True
    )
