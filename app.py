from email.header import Header
from flask import Flask, render_template
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import random
import string
import hashlib
import base64
from typing import Any, Tuple, Dict
import webbrowser
import requests
from oauthlib.oauth2 import WebApplicationClient
from IPython.display import clear_output
#import SMCSOauth

app = Flask(__name__)


@app.route('/')
def index():
    return render_template ('index.html')

@app.route('/about')
def about():
    return render_template ('about.html')

@app.route('/devices')
def devices():
    import SMCSOauth
    headers = { "Authorization": "Bearer " + SMCSOauth.access_token }
    list = requests.get("https://device-manager.smcs.io/printer/api/v1/devices", headers=headers)
    data = list.json()
    print(data)
    return data


if __name__ == '__main__':    
     app.run(debug=True)