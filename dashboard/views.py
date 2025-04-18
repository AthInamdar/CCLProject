import json  # Add this import at the top
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from .utils import SonarQubeAnalyzer, GeminiChatbot  # Import your custom classes
import logging
import os
import subprocess
import shutil
from django.views.generic import View
import csv
from django.conf import settings

logger = logging.getLogger(__name__)

# Initialize chatbot with API key from settings
chatbot = GeminiChatbot(api_key="AIzaSyCcknPR_lmjNLeLXTuGk_0BcInewKyJDIc")

@csrf_exempt
def chatbot_view(request):
    if request.method == 'POST':
        try:
            # Parse request data
            try:
                data = json.loads(request.body)
                user_input = data.get('message', '').strip()
                if not user_input:
                    return JsonResponse({'error': 'Empty message'}, status=400)
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
            
            # Get response from chatbot
            try:
                response = chatbot.generate_response(user_input)
                if not response:
                    raise ValueError("Empty response from chatbot")
                
                return JsonResponse({
                    'response': response,
                    'status': 'success'
                })
                
            except Exception as e:
                logger.error(f"Chatbot error: {str(e)}")
                return JsonResponse({
                    'error': 'Failed to generate response',
                    'details': str(e)
                }, status=500)
                
        except Exception as e:
            logger.error(f"Server error: {str(e)}")
            return JsonResponse({
                'error': 'Internal server error'
            }, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=400)


def dashboard_home(request):
    """Render the dashboard home with summary data from SonarQube report."""
    analyzer = SonarQubeAnalyzer()
    severity_counts = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
    
    for issue in analyzer.get_issues():
        severity = issue.get("severity", "").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    total_vulnerabilities = sum(severity_counts.values())
    high_severity_count = severity_counts["BLOCKER"] + severity_counts["CRITICAL"]
    
    security_percentage = max(
        0, 
        100 - ((severity_counts["CRITICAL"] * 3 + severity_counts["BLOCKER"] * 2) / 
              max(1, total_vulnerabilities) * 100)
    )
    adjusted_security_percentage = round(security_percentage, 2)

    context = {
        "total_vulnerabilities": total_vulnerabilities,
        "high_severity_count": high_severity_count,
        "security_percentage": adjusted_security_percentage,
        "insecurity_percentage": 100 - adjusted_security_percentage
    }
    
    return render(request, "dashboard/dashboard_home.html", context)


def issue_severity_data(request):
    analyzer = SonarQubeAnalyzer()
    severity_counts = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0}
    
    for issue in analyzer.get_issues():
        severity = issue.get("severity", "UNKNOWN")
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    return JsonResponse({
        "labels": list(severity_counts.keys()), 
        "data": list(severity_counts.values())
    })


def issue_type_data(request):
    analyzer = SonarQubeAnalyzer()
    type_counts = {"BUG": 0, "VULNERABILITY": 0, "CODE_SMELL": 0}
    
    for issue in analyzer.get_issues():
        issue_type = issue.get("type", "UNKNOWN")
        if issue_type in type_counts:
            type_counts[issue_type] += 1
    
    return JsonResponse({
        "labels": list(type_counts.keys()), 
        "data": list(type_counts.values())
    })


def sonarqube_report(request):
    """Render the SonarQube report page."""
    analyzer = SonarQubeAnalyzer()
    context = {"data": analyzer.data}
    return render(request, "dashboard/sonarqube_report.html", context)


def analyze_repo(request):
    if request.method == "POST":
        repo_url = request.POST.get("repo_url")

        # Clone the repository
        repo_name = repo_url.split("/")[-1].replace(".git", "")
        repo_path = f"/tmp/{repo_name}"

        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)  # Remove if already exists

        subprocess.run(["git", "clone", repo_url, repo_path], check=True)

        # Run security scanners
        run_security_scanners(repo_path)

        return JsonResponse({"message": "Analysis Started!"})
    
    return render(request, "urlinput.html")

def run_security_scanners(repo_path):
    security_logs = {}

    # Run SonarQube (Example)
    sonar_cmd = f"sonar-scanner -Dsonar.projectBaseDir={repo_path}"
    subprocess.run(sonar_cmd, shell=True)

    # Run Trivy for Vulnerability Scanning
    trivy_cmd = f"trivy fs {repo_path} -f json -o {repo_path}/trivy_report.json"
    subprocess.run(trivy_cmd, shell=True)

    # Collect logs
    logs_path = os.path.join(repo_path, "trivy_report.json")
    if os.path.exists(logs_path):
        with open(logs_path, "r") as f:
            security_logs["trivy"] = f.read()

    # Upload logs to Google Cloud Storage
    upload_to_gcs("security-logs-bucket", logs_path, f"logs/{repo_path}_security.json")

    return security_logs

from google.cloud import storage

def upload_to_gcs(bucket_name, source_file, destination_blob):
    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(destination_blob)
    blob.upload_from_filename(source_file)

    print(f"Uploaded {source_file} to {destination_blob} in {bucket_name}")

import requests

def trigger_cloud_function():
    function_url = "https://YOUR_CLOUD_FUNCTION_URL"
    response = requests.post(function_url, json={"message": "Start Preprocessing"})
    print(response.json())

# Card code

def load_csv_data():
    file_path = os.path.join(settings.BASE_DIR, 'dashboard\processed_sonarqube_report_1.csv')
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        cards = []
        for row in reader:
            text_range = row.get('textRange', '')
            flows = row.get('flows', '')

            card = {
                'severity': row.get('severity', ''),
                'component': row.get('component', ''),
                'project': row.get('project', ''),
                'line': row.get('line', ''),
                'textRange': text_range,
                'flows': flows,
                'message': row.get('message', ''),
                'effort': row.get('effort', ''),
                'tags': row.get('tags', '').strip('[]').replace("'", '').split(', ') if row.get('tags') else [],
            }
            cards.append(card)
        return cards

def card_view(request):
    cards = load_csv_data()
    return render(request, 'cards/cards.html', {'cards': cards})
