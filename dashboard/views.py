import json  # Add this import at the top
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from .utils import SonarQubeAnalyzer, GeminiChatbot  # Import your custom classes
import logging

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