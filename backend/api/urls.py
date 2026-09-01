from django.urls import path
from .views import (
    AnalyzeEmailView,
    AnalyzeEmlUploadView,
    ChatExplanationView,
    GenerateReportView,
    HistoryView,
    DashboardStatsView,
    OAuthCallbackView
)

urlpatterns = [
    path('api/analyze', AnalyzeEmailView.as_view(), name='api-analyze'),
    path('api/analyze-eml', AnalyzeEmlUploadView.as_view(), name='api-analyze-eml'),
    path('api/chat', ChatExplanationView.as_view(), name='api-chat'),
    path('api/report', GenerateReportView.as_view(), name='api-report'),
    path('api/history', HistoryView.as_view(), name='api-history'),
    path('api/dashboard', DashboardStatsView.as_view(), name='api-dashboard'),
    path('oauth2/callback', OAuthCallbackView.as_view(), name='oauth2-callback'),
]
