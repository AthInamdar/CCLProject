# security_dashboard/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    # Include all URLs from the dashboard app under the root URL
    path('', include('dashboard.urls')), 
    
    
]
