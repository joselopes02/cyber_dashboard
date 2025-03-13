from flask import Blueprint, render_template, request, abort, send_file, url_for
from models import URL, Download, Attack,Augmented_Attacks, db
import io
from extensions import cache

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')


def get_attacks_union():
    attack_query = db.session.query(
        Attack.id,
        Attack.date,
        Attack.source_ip,
        Attack.source_port,
        Attack.url,
        Attack.protocol,
        Attack.honeypot_name,
        Attack.md5,
        Attack.honeypot_ip,
        Attack.honeypot_service,
        Attack.city,
        Attack.country_name,
        Attack.continent,
        Attack.org,
        Attack.latitude,
        Attack.longitude
    )
    augmented_query = db.session.query(
        Augmented_Attacks.id,
        Augmented_Attacks.date,
        Augmented_Attacks.source_ip,
        Augmented_Attacks.source_port,
        Augmented_Attacks.url,
        Augmented_Attacks.protocol,
        Augmented_Attacks.honeypot_name,
        Augmented_Attacks.md5,
        Augmented_Attacks.honeypot_ip,
        Augmented_Attacks.honeypot_service,
        Augmented_Attacks.city,
        Augmented_Attacks.country_name,
        Augmented_Attacks.continent,
        Augmented_Attacks.org,
        Augmented_Attacks.latitude,
        Augmented_Attacks.longitude
    )
    # Use union_all to combine both queries. If you need only distinct rows, use .union() instead.
    return attack_query.union_all(augmented_query).subquery()


@dashboard_bp.route('/')
@cache.cached(timeout=600, query_string=True)
def dashboard():
    search_query = request.args.get('search', '')
    view = request.args.get('view', 'links')
    links_page = int(request.args.get('links_page', 1))
    payload_page = int(request.args.get('payload_page', 1))
    per_page = int(request.args.get('per_page', 20))
    
    attacks_union = get_attacks_union()
    print(attacks_union)
    rows = db.session.query(attacks_union).limit(5).all()
    for row in rows:
        print(dict(row._mapping))
    
    links_query = db.session.query(
        attacks_union.attacks_date,
        attacks_union.attacks_url,
        attacks_union.attacks_protocol,
        attacks_union.attacks_honeypot_name,
        URL.threat_names,
        URL.shasum,
    ).join(URL, attacks_union.url == URL.url, isouter=True
    ).filter(attacks_union.url != None, attacks_union.url != '')
    
    if search_query:
        links_query = links_query.filter(
            (attacks_union.attacks_url.startswith(search_query)) |
            (attacks_union.attacks_protocol.startswith(search_query)) |
            (attacks_union.attacks_honeypot_name.startswith(search_query)) |
            (URL.threat_names.startswith(search_query)) |
            (attacks_union.attacks_date.startswith(search_query)) 
        )
    links_paginated = links_query.paginate(page=links_page, per_page=per_page, error_out=False)
    
    payloads_query = db.session.query(
        attacks_union.attacks_date,
        attacks_union.md5,
        attacks_union.attacks_protocol,
        attacks_union.attacks_honeypot_name,
        Download.type,
    ).join(Download, attacks_union.attacks_md5 == Download.md5, isouter=True
    ).filter(attacks_union.attacks_md5 != None, attacks_union.attacks_md5 != '')
    
    if search_query:
        payloads_query = payloads_query.filter(
            (attacks_union.attacks_md5.startswith(search_query)) |
            (Download.type.attacks_startswith(search_query)) |
            (attacks_union.attacks_protocol.startswith(search_query)) |
            (attacks_union.attacks_date.startswith(search_query)) |
            (attacks_union.attacks_honeypot_name.startswith(search_query))
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
@cache.cached(timeout=600)
def record_detail(record_type, identifier):
    attacks_union = get_attacks_union()
    
    if record_type == 'link':
        record = db.session.query(
                    attacks_union.attacks_date,
                    attacks_union.attacks_source_ip,
                    attacks_union.attacks_source_port,
                    attacks_union.attacks_url,
                    attacks_union.attacks_protocol,
                    attacks_union.attacks_honeypot_name,
                    attacks_union.attacks_latitude,      
                    attacks_union.attacks_longitude, 
                    URL.threat_names,
                    URL.shasum,
                    URL.malicious_flags,
                    URL.times_submitted,
                    URL.reputation
                ).join(URL, attacks_union.attacks_url == URL.url, isouter=True
                ).filter(URL.shasum == identifier).first_or_404()
        download_record = Download.query.filter_by(sha256=record.shasum).first()
        return render_template('record_detail.html', record=record, record_type=record_type, download_record=download_record)
    
    elif record_type == 'payload':
        record = db.session.query(
                    attacks_union.attacks_date, 
                    attacks_union.attacks_md5,
                    attacks_union.attacks_source_ip,
                    attacks_union.attacks_source_port, 
                    attacks_union.attacks_protocol, 
                    attacks_union.attacks_honeypot_name,
                    attacks_union.attacks_latitude,      
                    attacks_union.attacks_longitude, 
                    Download.type, 
                    Download.reputation, 
                    Download.times_submitted, 
                    Download.file_size,
                    Download.popular_label, 
                    Download.malicious_flags
                ).join(Download, attacks_union.attacks_md5 == Download.md5, isouter=True
                ).filter(attacks_union.attacks_md5 == identifier).first_or_404()
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
