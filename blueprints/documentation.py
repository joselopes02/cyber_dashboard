from flask import Blueprint, render_template

documentation_bp = Blueprint('documentation', __name__, url_prefix='/documentation')

@documentation_bp.route('/')
def documentation():
    return render_template('documentation.html')
