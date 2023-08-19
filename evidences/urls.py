from django.urls import path
from evidences import views

urlpatterns = [
    path('evidences/', views.evidences, name='evidences'),
    path('api/evidences/', views.EvidenceAPIView.as_view()),
    path('api/evidences/<int:dump_id>/', views.EvidenceDetailApiView.as_view()),
    path('api/evidences/case/<int:case_id>/', views.CaseEvidenceApiView.as_view()),

] 