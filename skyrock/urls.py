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
    #url(r'^user/$', views.UserView.as_view(), name='user-view'),

    
    url(r'^admin/club/$', views.AdminClubCreateView.as_view(), name='user-course-view'),
    url(r'^admin/club/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminClubView.as_view(), name='user-course-view'),
    url(r'^admin/badge/$', views.AdminBadgeCreateView.as_view(), name='user-badge-view'),
    url(r'^admin/badge/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminBadgeView.as_view(), name='user-badge-view'),
    
    url(r'^admin/booking/$', views.CreateAdminBookingView.as_view(), name='user-booking-view'),
    url(r'^admin/booking/(?P<booking>([a-zA-Z0-9\_\-]+))/$', views.AdminBookingView.as_view(), name='user-node-view'),

    # url(r'^staff/badge/$', views.CreateAdminBadgeView.as_view(), name='user-node-view'),
    # url(r'^staff/badge/(?P<booking>([a-zA-Z0-9\_\-]+))/$', views.AdminBadgeView.as_view(), name='user-node-view'),

    url(r'^admin/student/$', views.AdminStudentCreateView.as_view(), name='user-student-view'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminStudentView.as_view(), name='user-node-view'),
    #url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/attendance/$', views.AdminStudentAttendanceView.as_view(), name='user-node-view'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/club/$', views.AdminClubCreateView.as_view(), name='user-club-view'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/club/(?P<club>([a-zA-Z0-9\_\-]+))/$', views.AdminClubView.as_view(), name='user-club-add'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/club/(?P<club>([a-zA-Z0-9\_\-]+))/badge/$', views.AdminBadgeAdd.as_view(), name='user-badge-add'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/booking/$', views.StudentBookingListView.as_view(), name='user-node-view'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/booking/(?P<booking>([a-zA-Z0-9\_\-]+))/$', views.AdminBookingView.as_view(), name='user-node-view'),
    # url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/badge/$', views.AdminStudentBadgeListView.as_view(), name='user-node-view'),


    url(r'^admin/client/$', views.AdminClientCreateView.as_view(), name='user-parent-view'),
    url(r'^admin/client/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminClientView.as_view(), name='user-node-view'),
    # url(r'^staff/parent/(?P<id>([a-zA-Z0-9\_\-]+))/sale/$', views.AdminParentSaleCreateView.as_view(), name='user-node-view'),
    # url(r'^staff/parent/(?P<id>([a-zA-Z0-9\_\-]+))/sale/(?P<booking>([a-zA-Z0-9\_\-]+))$', views.AdminParentSaleView.as_view(), name='user-node-view'),

    
      

    
)

urlpatterns = format_suffix_patterns(urlpatterns)
