from django.urls import path
from . import views
urlpatterns = [
    path('',views.election_list,name='election_list'),
    path('<int:election_id>/cast/',views.cast_vote,name='cast_vote'),
    path('<int:election_id>/results/',views.view_results,name='view_results'),
]