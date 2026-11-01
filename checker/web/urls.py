from django.urls import path

from checker.web import views

urlpatterns = [
    path("", views.fleet_page, name="fleet"),
    path("hosts/<path:name>/evidence", views.evidence_page, name="evidence"),
    path("hosts/<path:name>", views.host_page, name="host"),
    path("threats", views.threats_page, name="threats"),
    path("activity", views.activity_page, name="activity"),
    path("decide", views.decide_page, name="decide"),
    path("decide/baseline", views.baseline_accept, name="baseline_accept"),
    path("decide/approve", views.rule_approve, name="rule_approve"),
    path("decide/refuse", views.rule_refuse, name="rule_refuse"),
    path("decide/ask", views.rules_ask, name="rules_ask"),
    path("checks", views.checks_page, name="checks"),
    path("checks/new", views.check_new, name="check_new"),
    path("checks/start", views.check_start, name="check_start"),
    path("checks/analyze", views.analyze_start, name="analyze_start"),
    path("checks/<int:run_id>", views.check_page, name="check"),
    path("checks/<int:run_id>/stop", views.check_stop, name="check_stop"),
    path("login", views.login_page, name="login"),
    path("logout", views.logout_page, name="logout"),
    path("two-factor", views.two_factor_page, name="two_factor"),
    path("two-factor/setup", views.two_factor_setup, name="two_factor_setup"),
    path("two-factor/start", views.two_factor_start, name="two_factor_start"),
    path("two-factor/turn-on", views.two_factor_turn_on, name="two_factor_turn_on"),
    path("two-factor/manage", views.two_factor_manage, name="two_factor_manage"),
    path("two-factor/new-codes", views.two_factor_new_codes, name="two_factor_new_codes"),
    path("two-factor/codes-saved", views.two_factor_codes_saved, name="two_factor_codes_saved"),
    path("two-factor/turn-off", views.two_factor_turn_off, name="two_factor_turn_off"),
    path("setup/<str:token>", views.setup_page, name="setup"),
    path("style.css", views.stylesheet, name="style"),
    path("fonts/<str:name>", views.font, name="font"),
]

handler400 = "checker.web.views.bad_request"
handler403 = "checker.web.views.forbidden"
handler404 = "checker.web.views.not_found"
handler500 = "checker.web.views.server_error"
