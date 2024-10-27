from django.urls import path
from .views import EvidencePluginsView, PluginArtefactsView, TimelinerArtefactsView, TimelinerTask

urlpatterns = [
    path(
        "evidence/<int:evidence_id>/plugins/",
        EvidencePluginsView.as_view(),
        name="evidence-plugins",
    ),
    path(
        "evidence/<int:evidence_id>/plugin/<str:plugin_name>/",
        PluginArtefactsView.as_view(),
        name="evidence-plugin-artefacts",
    ),
    path('evidence/<int:evidence_id>/plugin/<str:plugin_name>/artefacts/', TimelinerArtefactsView.as_view()),
    path('evidence/tasks/timeliner/',  TimelinerTask.as_view())
]
