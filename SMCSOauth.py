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
import json
import certifi
import urllib3



class OAuthHttpServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)
        self.authorization_code = ""

class OAuthHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write("<script type=\"application/javascript\">window.close();</script>".encode("UTF-8"))
        
        parsed = parse.urlparse(self.path)

        qs = parse.parse_qs(parsed.query)
        
        self.server.authorization_code = qs["code"][0]


def generate_code() -> Tuple[str, str]:
    rand = random.SystemRandom()
    code_verifier = ''.join(rand.choices(string.ascii_letters + string.digits, k=128))

    code_sha_256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    b64 = base64.urlsafe_b64encode(code_sha_256)
    code_challenge = b64.decode('utf-8').replace('=', '')

    #print(code_challenge + '\n')
    #print(code_verifier + '\n')
    return (code_verifier, code_challenge)

def login(config: Dict[str, Any]) -> str:
    with OAuthHttpServer(('', config["port"]), OAuthHttpHandler) as httpd:
        client = WebApplicationClient(config["client_id"])
        
        code_verifier, code_challenge = generate_code()

        auth_uri = client.prepare_request_uri(config["auth_uri"], redirect_uri=config["redirect_uri"], 
            scope=config["scopes"], state="test_doesnotmatter", code_challenge= code_challenge, code_challenge_method = "S256" )

        webbrowser.open_new(auth_uri)

        httpd.handle_request()

        auth_code = httpd.authorization_code

        data = {
            "code": auth_code,
            "client_id": config["client_id"],
            "grant_type": "authorization_code",
            "scopes": config["scopes"],
            "redirect_uri": config["redirect_uri"],
            "code_verifier": code_verifier
        }

        response = requests.post(config["token_uri"], data=data, verify=False)

        access_token = response.json()["access_token"]
        clear_output()

        print("Logged in successfully")
        print('\n access+token = ' + access_token + '\n')
        return access_token

config = {
    "port": 8080,
    "client_id": "cc8fba50-e23b-4835-b59b-38ae4c134de4",
    "redirect_uri": f"https://smcs-app.herokuapp.com/",
    "auth_uri": "https://account.starmicronicscloud.com/retailer/signin/oauth2/v2.0/authorize",
    "token_uri": "https://account.starmicronicscloud.com/retailer/signin/oauth2/v2.0/token",
    "scopes": [ "https://starmicronicscloud.com/printer-manager/configurations", 
                "https://starmicronicscloud.com/printer-manager/devices ", 
                "https://starmicronicscloud.com/printer-manager/receipts" ]
}

access_token = login(config)
headers = { "Authorization": "Bearer " + access_token }

#response = requests.get("https://localhost:44301/weatherforecast", headers=headers, verify=False)

#print(json.dumps(response.json(), indent=4))