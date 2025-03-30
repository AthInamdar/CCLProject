from django.db import models

class SecurityLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    tool_name = models.CharField(max_length=50)   # e.g., SonarQube, Trivy, etc.
    raw_data = models.JSONField()                # Store entire JSON scan logs

    def __str__(self):
        return f"{self.tool_name} log at {self.timestamp}"

class Vulnerability(models.Model):
    log = models.ForeignKey(SecurityLog, on_delete=models.CASCADE, related_name='vulnerabilities')
    title = models.CharField(max_length=200)
    severity = models.CharField(max_length=20)   # e.g., LOW, MEDIUM, HIGH, CRITICAL
    description = models.TextField()
    recommendation = models.TextField()

    def __str__(self):
        return f"{self.title} - {self.severity}"
