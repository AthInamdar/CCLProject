from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_home, name='dashboard_home'),
    path('sonarqube/', views.sonarqube_report, name='sonarqube_report'),
    path('chatbot/', views.chatbot_view, name='chatbot'),
    path('urlinput/', views.analyze_repo, name='urlinput'),
    path('cards/', views.card_view, name='card_view'),
]