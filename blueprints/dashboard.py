from flask import Blueprint, render_template, request, abort, send_file, url_for
from ..models import URL, Download, Attack, Augmented_Attacks, db
import io
from ..extensions import cache

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')



# Encoding and decoding functions clearly defined:
def simple_encode(url: str) -> str:
    return url.replace(":", "%253A").replace("/", "%252F")


def simple_decode(encoded_url: str) -> str:
    return encoded_url.replace("%253A", ":").replace("%252F", "/")

# Register custom Jinja filter directly:
@dashboard_bp.app_template_filter('simple_encode')
def simple_encode_filter(url: str):
    return simple_encode(url)


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
        Attack.longitude.label("longitude"),
        db.literal('attack').label('source')  # clearly added source field
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
        Augmented_Attacks.longitude.label("longitude"),
        db.literal('augmented_attack').label('source')  # clearly added source field
    )

    return attack_query.union_all(augmented_query).subquery()




@dashboard_bp.route('/')
@cache.cached(timeout=600, query_string=True)
def dashboard():
    search_query = request.args.get('search', '').strip()
    view = request.args.get('view', 'links')
    links_page = int(request.args.get('links_page', 1))
    payload_page = int(request.args.get('payload_page', 1))
    per_page = int(request.args.get('per_page', 20))

    attacks_union = get_attacks_union()

    # Links query optimized
    links_query = db.session.query(
        attacks_union.c.id,                  # clearly add this line
        attacks_union.c.source, 
        attacks_union.c.date,
        attacks_union.c.url,
        attacks_union.c.protocol,
        attacks_union.c.honeypot_name,
        URL.threat_names,
        URL.shasum
    ).join(URL, attacks_union.c.url == URL.url, isouter=True)\
     .filter(attacks_union.c.url.isnot(None), attacks_union.c.url != '')

    # Payload query optimized
    payloads_query = db.session.query(
        attacks_union.c.date,
        attacks_union.c.md5,
        attacks_union.c.protocol,
        attacks_union.c.honeypot_name,
        Download.type,
    ).join(Download, attacks_union.c.md5 == Download.md5, isouter=True
    ).filter(attacks_union.c.md5 != None)

    if search_query:
        search_like = f"{search_query}%"
        links_query = links_query.filter(
            (attacks_union.c.url.ilike(search_query+'%')) |
            (attacks_union.c.protocol.ilike(search_query+'%')) |
            (attacks_union.c.honeypot_name.ilike(search_query)) |
            (URL.threat_names.ilike(search_query)) |
            (attacks_union.c.date.ilike(search_query))
        )

        payloads_query = payloads_query.filter(
            (attacks_union.c.md5.ilike(search_query)) |
            (attacks_union.c.protocol.ilike(search_query)) |
            (attacks_union.c.honeypot_name.ilike(search_query)) |
            (Download.type.ilike(search_query)) |
            (attacks_union.c.date.ilike(search_query))
        )

    links_paginated = links_query.order_by(attacks_union.c.date.desc()) \
        .paginate(page=links_page, per_page=per_page, error_out=False)
    
    payloads_paginated = payloads_query.order_by(attacks_union.c.date.desc()) \
        .paginate(page=payload_page, per_page=per_page, error_out=False)

    return render_template(
        'dashboard.html',
        view=view,
        links=links_paginated.items,
        payloads=payloads_paginated.items,
        links_paginated=links_paginated,
        payloads_paginated=payloads_paginated,
        search_query=search_query
    )



@dashboard_bp.app_template_filter('simple_encode')
def simple_encode_filter(url: str):
    return simple_encode(url)


@dashboard_bp.route('/record/<record_type>/<source>/<int:identifier>')
@cache.cached(timeout=600)
def record_detail(record_type, identifier):
    from urllib.parse import unquote
    
    attacks_union = get_attacks_union()
    
    if record_type == 'link':
        decoded_identifier = identifier.replace("%253A", ":").replace("%252F", "/")
        
        record = db.session.query(
                    attacks_union.c.id,
                    attacks_union.c.date,
                    attacks_union.c.source_ip,
                    attacks_union.c.source_port,
                    attacks_union.c.url,
                    attacks_union.c.protocol,
                    attacks_union.c.honeypot_name,
                    attacks_union.c.latitude,      
                    attacks_union.c.longitude,
                    attacks_union.c.source,
                    URL.threat_names,
                    URL.shasum,
                    URL.malicious_flags,
                    URL.times_submitted,
                    URL.reputation
                ).join(URL, attacks_union.c.url == URL.url, isouter=True
                ).filter(attacks_union.c.id == identifier, attacks_union.c.source == source).first_or_404()
        download_record = Download.query.filter_by(sha256=record.shasum).first()
        return render_template('record_detail.html', record=record, record_type=record_type, download_record=download_record)

    elif record_type == 'payload':
        record = db.session.query(
                    attacks_union.c.date, 
                    attacks_union.c.md5,
                    attacks_union.c.source_ip,
                    attacks_union.c.source_port, 
                    attacks_union.c.protocol, 
                    attacks_union.c.honeypot_name,
                    attacks_union.c.latitude,      
                    attacks_union.c.longitude, 
                    Download.type, 
                    Download.reputation, 
                    Download.times_submitted, 
                    Download.file_size,
                    Download.popular_label, 
                    Download.malicious_flags
                ).join(Download, attacks_union.c.md5 == Download.md5, isouter=True
                ).filter(attacks_union.c.md5 == identifier).first_or_404()
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
