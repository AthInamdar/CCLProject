import json
import os
import google.generativeai as genai
import time
from django.conf import settings
import logging
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)
class SonarQubeAnalyzer:
    """Analyzes SonarQube reports and provides security insights."""
    
    SEVERITY_LEVELS = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
    ISSUE_TYPES = ["BUG", "VULNERABILITY", "CODE_SMELL"]
    
    def __init__(self, report_path: Optional[str] = None):
        """
        Initialize the analyzer with a SonarQube report.
        
        Args:
            report_path: Custom path to the SonarQube report JSON file.
                        If None, looks in default locations.
        """
        self.report_path = self._locate_report_file(report_path)
        self.data = self._load_report()
        
    def _locate_report_file(self, report_path: Optional[str]) -> Optional[str]:
        """Try to locate the report file in common locations."""
        possible_paths = [
            report_path,
            os.path.join(settings.BASE_DIR, "sonarqube_report.json"),
            os.path.join(os.path.dirname(__file__), "sonarqube_report.json"),
            "sonarqube_report.json"
        ]
        
        for path in possible_paths:
            if path and os.path.exists(path):
                logger.info(f"Found SonarQube report at: {path}")
                return path
                
        logger.warning("SonarQube report not found in any standard location")
        return None
        
    def _load_report(self) -> Dict:
        """Load and validate the SonarQube report."""
        if not self.report_path:
            return {"issues": []}
            
        try:
            with open(self.report_path, "r") as file:
                data = json.load(file)
                if not isinstance(data, dict) or "issues" not in data:
                    raise ValueError("Invalid report format: 'issues' key missing")
                return data
                
        except FileNotFoundError:
            logger.error(f"SonarQube report not found at {self.report_path}")
            return {"issues": []}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in SonarQube report: {str(e)}")
            return {"issues": []}
        except Exception as e:
            logger.error(f"Unexpected error loading report: {str(e)}")
            return {"issues": []}
    
    def get_issues(self, filters: Optional[Dict] = None) -> List[Dict]:
        """
        Get issues with optional filtering.
        
        Args:
            filters: Dictionary of filters (e.g., {'severity': 'CRITICAL'})
            
        Returns:
            List of filtered issues
        """
        issues = self.data.get("issues", [])
        
        if not filters:
            return issues
            
        filtered_issues = []
        for issue in issues:
            match = True
            for key, value in filters.items():
                if issue.get(key) != value:
                    match = False
                    break
            if match:
                filtered_issues.append(issue)
                
        return filtered_issues
    
    def analyze_query(self, query: str, context_history: Optional[List] = None) -> Dict:
        """
        Analyze the SonarQube report based on a natural language query.
        
        Args:
            query: User's natural language query
            context_history: Previous conversation context
            
        Returns:
            Dictionary containing:
            - response: Text response
            - issues: List of matched issues
            - context: Updated context
        """
        query_lower = query.lower().strip()
        context_history = context_history or []
        
        # Handle empty query
        if not query_lower:
            return {
                "response": "Please provide a query about your security issues.",
                "issues": [],
                "context": context_history
            }
        
        # Check for greetings
        if any(greeting in query_lower for greeting in ["hi", "hello", "hey"]):
            return {
                "response": "Hello! I'm your security assistant. How can I help you today?",
                "issues": [],
                "context": context_history
            }
        
        # Get relevant issues
        matched_issues = self._match_issues_to_query(query_lower)
        response_text = self._generate_response_text(query_lower, matched_issues, context_history)
        
        # Update context
        new_context = context_history.copy()
        new_context.append({"query": query, "response": response_text})
        
        return {
            "response": response_text,
            "issues": matched_issues,
            "context": new_context[-5:]  # Keep last 5 messages as context
        }
    
    def _match_issues_to_query(self, query_lower: str) -> List[Dict]:
        """Match issues to the user's query."""
        issues = self.get_issues()
        matched_issues = []
        
        # Component filtering
        component_keywords = {
            "auth": ["auth", "login", "authentication"],
            "api": ["api", "endpoint", "rest"],
            "db": ["database", "db", "sql", "query"]
        }
        
        # Severity keywords
        severity_keywords = {
            "BLOCKER": ["blocker", "critical", "urgent"],
            "CRITICAL": ["critical", "high", "severe"],
            "MAJOR": ["major", "medium"],
            "MINOR": ["minor", "low"]
        }
        
        # Issue type keywords
        type_keywords = {
            "BUG": ["bug", "error", "crash"],
            "VULNERABILITY": ["vulnerability", "security", "risk", "exploit"],
            "CODE_SMELL": ["smell", "quality", "refactor"]
        }
        
        for issue in issues:
            issue_text = (
                f"{issue.get('message', '')} "
                f"{issue.get('component', '')} "
                f"{issue.get('severity', '')} "
                f"{' '.join(issue.get('tags', []))}"
            ).lower()
            
            # Check component matches
            component_match = False
            for comp, keywords in component_keywords.items():
                if any(kw in query_lower for kw in keywords) or any(kw in issue_text for kw in keywords):
                    component_match = True
                    break
            
            # Check severity matches
            severity_match = False
            for sev, keywords in severity_keywords.items():
                if any(kw in query_lower for kw in keywords) or issue.get('severity') == sev:
                    severity_match = True
                    break
            
            # Check type matches
            type_match = False
            for typ, keywords in type_keywords.items():
                if any(kw in query_lower for kw in keywords) or issue.get('type') == typ:
                    type_match = True
                    break
            
            # If any category matches, include the issue
            if component_match or severity_match or type_match:
                matched_issues.append({
                    "id": issue.get("key", "N/A"),
                    "component": issue.get("component", "unknown").split(":")[-1],
                    "line": issue.get("line", "N/A"),
                    "message": issue.get("message", "No details provided"),
                    "severity": issue.get("severity", "N/A"),
                    "type": issue.get("type", "UNKNOWN"),
                    "tags": issue.get("tags", []),
                    "suggestion": self._get_suggestion(issue)
                })
                
        return matched_issues
    
    def _get_suggestion(self, issue: Dict) -> str:
        """Generate a suggestion based on issue type."""
        issue_type = issue.get("type", "").upper()
        severity = issue.get("severity", "").upper()
        
        suggestions = {
            "VULNERABILITY": {
                "BLOCKER": "This is a critical security risk that should be fixed immediately.",
                "CRITICAL": "This security vulnerability requires urgent attention.",
                "DEFAULT": "Consider implementing security best practices to address this vulnerability."
            },
            "BUG": {
                "BLOCKER": "This serious bug is causing system failures and must be fixed immediately.",
                "CRITICAL": "This bug is impacting system functionality and should be prioritized.",
                "DEFAULT": "Review the error conditions and implement proper error handling."
            },
            "CODE_SMELL": {
                "DEFAULT": "This code quality issue should be addressed to improve maintainability."
            },
            "DEFAULT": "Review this issue and consider appropriate remediation."
        }
        
        # Get the most specific suggestion available
        return (suggestions.get(issue_type, {}).get(severity) or
                suggestions.get(issue_type, {}).get("DEFAULT") or
                suggestions.get("DEFAULT"))
    
    def _generate_response_text(self, query: str, issues: List[Dict], context: List) -> str:
        """Generate a natural language response based on the matched issues."""
        if not issues:
            if "authentication" in query:
                return "No authentication-related issues found."
            if any(word in query for word in ["vulnerability", "security", "risk"]):
                return "No security vulnerabilities found in the report."
            return "No matching issues found. Try being more specific or ask about different categories."
        
        # Group issues by severity for the response
        severity_counts = {level: 0 for level in self.SEVERITY_LEVELS}
        for issue in issues:
            severity = issue.get("severity", "").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Build response
        response_parts = []
        total_issues = len(issues)
        
        if total_issues == 1:
            response_parts.append("I found 1 matching issue:")
        else:
            response_parts.append(f"I found {total_issues} matching issues:")
            
            # Add severity breakdown
            severity_info = []
            for level in self.SEVERITY_LEVELS:
                if severity_counts[level] > 0:
                    severity_info.append(f"{severity_counts[level]} {level.lower()}")
            if severity_info:
                response_parts.append(f"Severity breakdown: {', '.join(severity_info)}")
        
        # Add context-aware follow-up if we have previous messages
        if context:
            last_query = context[-1].get("query", "")
            if "fix" in last_query.lower() and "how" in query.lower():
                response_parts.append("\nFor detailed fix instructions, ask about a specific issue number.")
        
        return "\n".join(response_parts)

class GeminiChatbot:
    def __init__(self, api_key):
        try:
            genai.configure(api_key=api_key)
            # Use the most widely available model
            self.model = genai.GenerativeModel("gemini-2.0-flash")
            self.ready = True
        except Exception as e:
            logger.error(f"Gemini initialization failed: {str(e)}")
            self.ready = False
            self.model = None

    def generate_response(self, user_input):
        if not self.ready or not self.model:
            return "Chatbot service is currently unavailable."

        user_input = user_input.strip().lower()
        
        # Handle basic commands locally
        if user_input in ["hi", "hello", "hey"]:
            return "Hello! I'm your security assistant. How can I help you today?"
        if user_input in ["exit", "quit", "bye"]:
            return "Goodbye! Stay secure! 🔒"

        # Get issues from SonarQube
        analyzer = SonarQubeAnalyzer()
        sonarqube_issues = analyzer.get_issues()
        
        try:
            if "vulnerabilities" in user_input or "issues" in user_input:
                vulnerabilities = "\n".join(
                    [f"{i+1}. {issue['message']} (Severity: {issue['severity']})" 
                     for i, issue in enumerate(sonarqube_issues)]
                )
                return f"Here are the detected vulnerabilities:\n{vulnerabilities}\nWhich one would you like more details on?"
            
            elif "fix" in user_input or "solve" in user_input:
                return "Please specify the issue number or describe the problem you need help with."
            
            elif user_input.isdigit() and 1 <= int(user_input) <= len(sonarqube_issues):
                issue = sonarqube_issues[int(user_input) - 1]
                prompt = self._create_issue_prompt(issue)
                return self._safe_generate_content(prompt)
            
            else:
                prompt = self._create_general_prompt(user_input, sonarqube_issues)
                return self._safe_generate_content(prompt)
                
        except Exception as e:
            logger.error(f"Response generation error: {str(e)}")
            return "I encountered an error processing your request. Please try again."

    def _safe_generate_content(self, prompt):
        """Safe wrapper around generate_content with retries"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(prompt)
                if response.text:
                    return response.text
                raise ValueError("Empty response from Gemini")
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                time.sleep(2 ** attempt)  # Exponential backoff
        return "I'm having trouble generating a response. Please try again later."

    def _create_issue_prompt(self, issue):
        return f"""As a security expert, analyze this issue:
        - File: {issue['component']}
        - Line: {issue['line']}
        - Severity: {issue['severity']}
        - Description: {issue['message']}
        - Tags: {', '.join(issue.get('tags', []))}
        
        Provide:
        1. Risk assessment
        2. Exploitation potential  
        3. Fix with code examples
        4. Best practices
        Use markdown formatting with clear sections."""

    def _create_general_prompt(self, query, issues):
        return f"""As a security consultant, answer this query:
        Question: "{query}"
        Context: {json.dumps(issues[:3], indent=2)}
        
        Provide a detailed, professional response with:
        - Clear explanation
        - Practical advice
        - Security best practices
        Format your response with proper headings."""