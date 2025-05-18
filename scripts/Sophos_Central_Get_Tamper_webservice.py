from flask import Flask, request, jsonify
import requests
import configparser
import getpass
import re
import sys

app = Flask(__name__)

def sanitize_hostname(hostname):
    if len(hostname) > 10:
        raise ValueError("Computername must be lower 11")
    if not re.match("^[a-zA-Z0-9]+$", hostname):
        raise ValueError("Computername must be alphanumeric")
    return hostname

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
        'grant_type': 'client_credentials',
        'client_id': client,
        'client_secret': secret,
        'scope': 'token'
    }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    headers = {'Authorization': f"Bearer {json_token['access_token']}"}
    post_headers = {
        'Authorization': f"Bearer {json_token['access_token']}",
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    return headers, post_headers

def get_whoami(headers):
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    organization_type = whoami["idType"]
    if whoami["idType"] == "partner":
        organization_header = "X-Partner-ID"
    elif whoami["idType"] == "organization":
        organization_header = "X-Organization-ID"
    else:
        organization_header = "X-Tenant-ID"
    organization_id = whoami["id"]
    region_url = whoami.get('apiHosts', {}).get("dataRegion", None)
    return organization_id, organization_header, organization_type, region_url

def get_all_sub_estates(headers, organization_header, organization_id, organization_type):
    headers[organization_header] = organization_id
    sub_estate_list = []
    request_sub_estates = requests.get(f"https://api.central.sophos.com/{organization_type}/v1/tenants?pageTotal=True", headers=headers)
    sub_estate_json = request_sub_estates.json()
    total_pages = sub_estate_json["pages"]["total"]
    sub_estate_keys = ('id', 'name', 'dataRegion', 'showAs')
    while total_pages != 0:
        request_sub_estates = requests.get(f"https://api.central.sophos.com/{organization_type}/v1/tenants?page={total_pages}", headers=headers)
        sub_estate_json = request_sub_estates.json()
        for all_sub_estates in sub_estate_json["items"]:
            sub_estate_dictionary = {key: value for key, value in all_sub_estates.items() if key in sub_estate_keys}
            sub_estate_list.append(sub_estate_dictionary)
        total_pages -= 1
    del headers[organization_header]
    return sub_estate_list

def get_computer_id(sub_estate_token, url, hostname, headers):
    url = f"{url}/endpoints?hostnameContains={hostname}"
    headers['X-Tenant-ID'] = sub_estate_token
    request_computers = requests.get(url, headers=headers)
    if request_computers.status_code == 200:
        response_json = request_computers.json()
        if 'items' in response_json and response_json['items']:
            for item in response_json['items']:
                if 'id' in item:
                    return item['id']
    return "NULL"

def get_tamper_password(machine_id, tamper_url, headers):
    password_url = f"{tamper_url}/endpoints/{machine_id}/tamper-protection"
    password_response = requests.get(password_url, headers=headers)
    if password_response.status_code == 200:
        return password_response.json()['password']
    else:
        return "NULL"

def read_config():
    config = configparser.ConfigParser()
    
    config.read('Sophos_Central.config')
    client_id = config['DEFAULT']['ClientID']
    client_secret = config['DEFAULT']['ClientSecret']
    if client_secret == '':
        client_secret = getpass.getpass(prompt='Enter Client Secret: ', stream=None)
    return client_id, client_secret

@app.route('/get-tamper-password', methods=['GET'])
def get_tamper_protection_password():
    hostname = request.args.get('hostname')
    if not hostname:
        return jsonify({"error": "You must provide computername"}), 400

    try:
        endpoint = sanitize_hostname(hostname)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    client_id, client_secret = read_config()
    token_url = 'https://id.sophos.com/api/v2/oauth2/token'
    headers, post_headers = get_bearer_token(client_id, client_secret, token_url)
    organization_id, organization_header, organization_type, region_url = get_whoami(headers)

    if organization_type != "tenant":
        sub_estate_list = get_all_sub_estates(headers, organization_header, organization_id, organization_type)
        for sub_estate in sub_estate_list:
            computer_id = get_computer_id(sub_estate['id'], f"https://api-{sub_estate['dataRegion']}.central.sophos.com/endpoint/v1", endpoint, headers)
            if computer_id != "NULL":
                tamper_password = get_tamper_password(computer_id, f"https://api-{sub_estate['dataRegion']}.central.sophos.com/endpoint/v1", headers)
                return jsonify({"tamper_protection_password": tamper_password})
    else:
        computer_id = get_computer_id(organization_id, f"{region_url}/endpoint/v1", endpoint, headers)
        tamper_password = get_tamper_password(computer_id, f"{region_url}/endpoint/v1", headers)
        return jsonify({"tamper_protection_password": tamper_password})

    return jsonify({"error": "Uable to find provided computername"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug=True)
