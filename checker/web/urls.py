from django.urls import path

from checker.web import views

urlpatterns = [
    path("", views.fleet_page, name="fleet"),
    path("login", views.login_page, name="login"),
    path("logout", views.logout_page, name="logout"),
    path("setup/<str:token>", views.setup_page, name="setup"),
    path("style.css", views.stylesheet, name="style"),
    path("fonts/<str:name>", views.font, name="font"),
]

handler400 = "checker.web.views.bad_request"
handler403 = "checker.web.views.forbidden"
handler404 = "checker.web.views.not_found"
handler500 = "checker.web.views.server_error"
