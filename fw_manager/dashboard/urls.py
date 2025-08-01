from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard_home, name="home"),
    path("rules/", views.list_rules, name="list_rules"),
    path("rules/add/", views.add_rule, name="add_rule"),
    path("rules/delete/<int:rule_id>/", views.delete_rule, name="delete_rule"),
    path("rules/apply/", views.apply_rules, name="apply_rules"),
    path("rules/system/", views.list_applied_rules, name="list_applied_rules"),
    path("dpi/fetch_logs/", views.fetch_logs, name="fetch_logs"),
    path("dpi/clear_logs/", views.clear_logs_view, name="clear_logs"),
    path("dpi/run/", views.dpi_control, name="dpi_control"),
]
