from django.urls import path
from test_app import views


app_name = 'test_app'
urlpatterns = [
    path("create-obj", views.create_obj_view, name="create-obj"),
    path("update-obj", views.update_obj_view, name="update-obj"),
]
