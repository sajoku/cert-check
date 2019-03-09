#!/usr/bin/env python3

from flask_api import FlaskAPI

from .cert_check import CertChecker


app = FlaskAPI(__name__)


@app.route("/<path:url>/", methods=['GET'])
def validate_certificate(url):
    return {'isvalid': CertChecker(url).check()}


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5050)
