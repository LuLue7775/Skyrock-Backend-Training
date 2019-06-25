from django.conf.urls import *
from rest_framework.urlpatterns import format_suffix_patterns

from . import views

urlpatterns = (
    # Public
    url(r'^$', views.root),
    
    url(r'^user/auth/register/$', views.RegisterView.as_view(), name='user-register'),
    url(r'^user/auth/login/$', views.LoginView.as_view(), name='user-login'),
    url(r'^user/auth/logout/$', views.LogoutView.as_view(), name='user-logout'),
    url(r'^user/auth/password/change/$', views.PasswordChangeView.as_view(), name='user-password-change'),
    url(r'^user/auth/password/reset/$', views.PasswordResetView.as_view(), name='user-password-reset'),
    
    url(r'^staff/course/$', views.AdminPathwayCreateView.as_view(), name='user-node-view'),
    url(r'^staff/course/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminPathwayView.as_view(), name='user-node-view'),
    
    url(r'^staff/booking/$', views.CreateAdminBookingView.as_view(), name='user-node-view'),
    url(r'^staff/booking/(?P<booking>([a-zA-Z0-9\_\-]+))/$', views.AdminBookingView.as_view(), name='user-node-view'),

    # url(r'^staff/badge/$', views.CreateAdminBadgeView.as_view(), name='user-node-view'),
    # url(r'^staff/badge/(?P<booking>([a-zA-Z0-9\_\-]+))/$', views.AdminBadgeView.as_view(), name='user-node-view'),

    url(r'^staff/student/$', views.AdminStudentCreateView.as_view(), name='user-node-view'),
    url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminStudentView.as_view(), name='user-node-view'),
    #url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/attendance/$', views.AdminStudentAttendanceView.as_view(), name='user-node-view'),
    url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/booking/$', views.StudentBookingListView.as_view(), name='user-node-view'),
    url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/booking/(?P<booking>([a-zA-Z0-9\_\-]+))$', views.AdminStudentBookingView.as_view(), name='user-node-view'),
    # url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/badge/$', views.AdminStudentBadgeListView.as_view(), name='user-node-view'),


    url(r'^staff/parent/$', views.AdminParentCreateView.as_view(), name='user-node-view'),
    url(r'^staff/parent/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminParentView.as_view(), name='user-node-view'),
    # url(r'^staff/parent/(?P<id>([a-zA-Z0-9\_\-]+))/sale/$', views.AdminParentSaleCreateView.as_view(), name='user-node-view'),
    # url(r'^staff/parent/(?P<id>([a-zA-Z0-9\_\-]+))/sale/(?P<booking>([a-zA-Z0-9\_\-]+))$', views.AdminParentSaleView.as_view(), name='user-node-view'),

    
      

    
)

urlpatterns = format_suffix_patterns(urlpatterns)
