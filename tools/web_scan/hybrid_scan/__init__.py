# tools/web_scan/hybrid_scan/__init__.py
from flask import Flask

app = Flask(__name__)

from tools.web_scan.hybrid_scan import main
