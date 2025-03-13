# app.py
from flask import Flask , redirect, url_for
from .config import Config

from .models import db
from blueprints.dashboard import dashboard_bp
from blueprints.statistics import statistics_bp
from blueprints.documentation import documentation_bp
from extensions import cache



def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize SQLAlchemy with the app
    db.init_app(app)

    # Initialize cache with a simple configuration 
    app.config['CACHE_TYPE'] = 'simple'
    app.config['CACHE_DEFAULT_TIMEOUT'] = 180  
    cache.init_app(app)
    
    # Register blueprints for modular routing
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(statistics_bp)
    app.register_blueprint(documentation_bp)

    # Home page route: redirect to dashboard
    @app.route('/')
    def home():
        return redirect(url_for('dashboard.dashboard'))
    
    return app
    
app = create_app()

if __name__ == '__main__':

    app.run(host="0.0.0.0",port=8888)
#if __name__ == '__main__':
#    app = create_app()
#    app.run(host="0.0.0.0",port=8888)
