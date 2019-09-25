from django.conf.urls import *
from rest_framework.urlpatterns import format_suffix_patterns

from . import views

urlpatterns = (
    # Public
    url(r'^$', views.root),
    
    url(r'^user/auth/register/$', views.UserRegisterView.as_view(), name='user-register'),
    url(r'^user/auth/login/$', views.LoginView.as_view(), name='user-login'),
    url(r'^user/auth/logout/$', views.LogoutView.as_view(), name='user-logout'),
    url(r'^user/auth/password/change/$', views.PasswordChangeView.as_view(), name='user-password-change'),
    url(r'^user/auth/password/reset/$', views.PasswordResetView.as_view(), name='user-password-reset'),
    url(r'^user/auth/create/(?P<client>([a-zA-Z0-9\_\-]+))/$', views.CreateUserView.as_view(), name='user-create'),
    
    url(r'^user/$', views.UserView.as_view(), name='user-view'),
    url(r'^user/client/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.UserClientView.as_view(), name='user-client-view'),
    url(r'^user/student/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.UserStudentView.as_view(), name='user-student-view'),
    url(r'^user/booking/$', views.CreateUserBookingView.as_view(), name='user-booking-view'),
    url(r'^user/booking/(?P<booking>([a-zA-Z0-9\_\-]+))/$', views.UserBookingView.as_view(), name='user-node-view'),


    url(r'^admin/auth/register/$', views.RegisterView.as_view(), name='admin-register'),
    url(r'^admin/auth/login/$', views.LoginView.as_view(), name='admin-login'),
    url(r'^admin/auth/logout/$', views.LogoutView.as_view(), name='admin-logout'),
    url(r'^admin/auth/password/change/$', views.PasswordChangeView.as_view(), name='admin-password-change'),
    url(r'^admin/auth/password/reset/$', views.PasswordResetView.as_view(), name='admin-password-reset'),
    url(r'^admin/auth/create/(?P<client>([a-zA-Z0-9\_\-]+))/$', views.CreateUserView.as_view(), name='admin-create'),
        
    url(r'^admin/club/$', views.AdminClubCreateView.as_view(), name='admin-course-view'),
    url(r'^admin/club/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminClubView.as_view(), name='admin-course-view'),
    
    url(r'^admin/badge/$', views.AdminBadgeCreateView.as_view(), name='user-badge-view'),
    url(r'^admin/badge/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminBadgeView.as_view(), name='user-badge-view'),
    
    url(r'^admin/session/$', views.CreateAdminSessionView.as_view(), name='admin-session-list'),
    url(r'^admin/session/(?P<class>([a-zA-Z0-9\_\-]+))/$', views.AdminSessionView.as_view(), name='admin-session-view'),

    url(r'^admin/booking/$', views.CreateAdminBookingView.as_view(), name='admin-booking-view'),
    url(r'^admin/booking/(?P<booking>([a-zA-Z0-9\_\-]+))/$', views.AdminBookingView.as_view(), name='user-node-view'),

    url(r'^admin/student/$', views.AdminStudentCreateView.as_view(), name='admin-students-view'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminStudentView.as_view(), name='admin-student-view'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/club/$', views.AdminClubCreateView.as_view(), name='user-club-view'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/club/(?P<club>([a-zA-Z0-9\_\-]+))/$', views.AdminClubView.as_view(), name='user-club-add'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/club/(?P<club>([a-zA-Z0-9\_\-]+))/badge/$', views.AdminBadgeAdd.as_view(), name='user-badge-add'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/booking/$', views.StudentBookingListView.as_view(), name='user-node-view'),
    url(r'^admin/student/(?P<id>([a-zA-Z0-9\_\-]+))/booking/(?P<booking>([a-zA-Z0-9\_\-]+))/$', views.AdminBookingView.as_view(), name='user-node-view'),

    url(r'^admin/client/$', views.AdminClientCreateView.as_view(), name='admin-parent-view'),
    url(r'^admin/client/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminClientView.as_view(), name='user-node-view'),
    url(r'^admin/client/(?P<id>([a-zA-Z0-9\_\-]+))/note/$', views.CreateClientNoteView.as_view(), name='create-client-note-view'),
    url(r'^admin/client/(?P<id>([a-zA-Z0-9\_\-]+))/note/(?P<note_id>([a-zA-Z0-9\_\-]+))/$', views.ClientNoteView.as_view(), name='client-note-view'),


  
)

urlpatterns = format_suffix_patterns(urlpatterns)
