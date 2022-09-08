import json
import subprocess
from investigations.celery import app
import hashlib
import requests
import shutil


def get_key() -> str:
    """Get virustotal API Key

    Returns:
        str: Virustotal API Key
    """
    # TODO Change API key managment
    with open("VIRUSTOTAL_KEY.txt") as f:
        KEY = f.readline()
    return KEY


@app.task(name="virustotal_filescan")
def virustotal_filescan(dump_path: str) -> dict:
    """Manage virustotal filescan

    Args:
        dump_path (str): Path of the file to scan

    Returns:
        dict: filescan results
    """
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
    """Check if filescan is done

    Args:
        analysis_id (str): Virustotal analysis identifier

    Returns:
        bool: True if filescan is done
    """
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    headers = {
        "Accept": "application/json",
        "x-apikey": get_key()
    }

    response = requests.get(url, headers=headers)
    result = json.loads(response.text)
    print(result)
    return result["data"]["attributes"]["status"] == "completed"

def upload_file(path: str) -> requests.Response:
    """Upload file for analysis

    Args:
        path (str): path to the file to upload

    Returns:
        requests.Response: response
    """
    url = "https://www.virustotal.com/api/v3/files"
    files = {"file": open(path, "rb")}
    headers = {
        "Accept": "application/json",
        "x-apikey": get_key()
    }
    response = requests.post(url, files=files, headers=headers)
    return response


def get_file_report(path: str) -> requests.Response:
    """Get file report based on sha256 hasg

    Args:
        path (str): path to the file

    Returns:
        requests.Response: reponse
    """
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
    """Get file data from analysis id

    Args:
        analysis_id (str): analysis id

    Returns:
        dict: response as dict
    """
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}/item"

    headers = {
        "Accept": "application/json",
        "x-apikey": get_key()
    }

    response = requests.get(url, headers=headers)
    return json.loads(response.text)

@app.task(name="get_widget_url")
def get_widget_url(id: str) -> str:
    """Get VT Augment widget url

    Args:
        id (str): Virustotal analysis id

    Returns:
        str: url
    """
    url = f"https://www.virustotal.com/api/v3/widget/url?query={id}"

    headers = {
        "Accept": "application/json",
        "X-Apikey": get_key()
    }

    response = requests.get(url, headers=headers)
    return json.loads(response.text)["data"]["url"]

@app.task(name="clamav_file")
def clamav_file(filepath: str) -> 'tuple[bool,str]':
    """Perform ClamAV analysis from file

    Args:
        filepath (str): Filepath of the file to analyse

    Returns:
        tuple[bool,str]: The boolean is true if the file is detected as malicious (or unable to analyse) and the string gives details on the detection
    """
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
    
@app.task(name="bulk_extractor")
def bulk_extractor(dump_path: str, output_path: str) -> None:
    """perform bulk extractor analysis and generated archives from the results

    Args:
        dump_path (str): Path of the dump to analyse
        output_path (str): Path for the results and the zip file
    """
    # Running Bulk Extractor
    print(f"Running bulk_extractor on {dump_path }")
    try:
        output = subprocess.check_output(['/home/linuxbrew/.linuxbrew/bin/bulk_extractor',
            dump_path, '-o', output_path],timeout=1200)
        print(output)
        # Compressing the results
        shutil.make_archive(f"{output_path}", 'zip', output_path)
    except subprocess.CalledProcessError as e:
        print(e.cmd)
        print(e.stdout)
        print(e.stderr)
