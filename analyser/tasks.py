import json
import subprocess
from investigations.celery import app
import hashlib
import requests


def get_key() -> str:
    # TODO Change API key managment
    with open("VIRUSTOTAL_KEY.txt") as f:
        KEY = f.readline()
    return KEY


@app.task(name="virustotal_filescan")
def virustotal_filescan(dump_path) -> dict:
    try:
        report = get_file_report(dump_path)
    except Exception as e:
        print(e)
    else:
        report = json.loads(report.text)
        if "error" not in report.keys():
            return report
        else:
            print(report["error"])
    return json.loads(upload_file(dump_path).text)

@app.task(name="is_filescan_done")
def is_filescan_done(analysis_id) -> bool:
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    headers = {
        "Accept": "application/json",
        "x-apikey": get_key()
    }

    response = requests.get(url, headers=headers)
    result = json.loads(response.text)
    print(result)
    return result["data"]["attributes"]["status"] == "completed"

def upload_file(path) -> requests.Response:
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": open(path, "rb")}
    headers = {
        "Accept": "application/json",
        "x-apikey": get_key()
    }
    response = requests.post(url, files=files, headers=headers)
    return response


def get_file_report(path) -> requests.Response:

    # Compute sha256
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash.hexdigest()}"

    headers = {
        "Accept": "application/json",
        "x-apikey": get_key()
    }

    response = requests.get(url, headers=headers)
    return response

@app.task(name="get_file_related_to_analysis")
def get_file_related_to_analysis(analysis_id: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}/item"

    headers = {
        "Accept": "application/json",
        "x-apikey": get_key()
    }

    response = requests.get(url, headers=headers)
    return json.loads(response.text)

@app.task(name="get_widget_url")
def get_widget_url(id: str) -> str:
    url = f"https://www.virustotal.com/api/v3/widget/url?query={id}"

    headers = {
        "Accept": "application/json",
        "X-Apikey": get_key()
    }

    response = requests.get(url, headers=headers)
    return json.loads(response.text)["data"]["url"]

@app.task(name="clamav_file")
def clamav_file(filepath: str) -> 'tuple[bool,str]':
    try:
        output = subprocess.check_output(['clamdscan', '-v','--fdpass', '--stream', filepath],timeout=120)
        print(output)
        return (False,"")
    except subprocess.CalledProcessError as e:
        print(e.cmd)
        print(e.output)
        print(e.stderr)
        if e.returncode == 1:
            return (True,e.output.decode().splitlines()[0].split(" ")[1])
        elif e.returncode == 2:
            return (True,"Unable to check for viruses")

    except Exception as e:
        return (True,"Unable to check for viruses. Unknown Error")
    
