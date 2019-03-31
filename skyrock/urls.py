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
    # url(r'^user/auth/password/reset/confirm/$', views.PasswordResetConfirmView.as_view(), name='user-password-reset-confirm'),
    #url(r'^user/auth/email/verify/resend/$', views.ResendVerifyEmailView.as_view(), name='user-resend-email-verify'),
    #url(r'^user/auth/email/verify/$', views.VerifyEmailView.as_view(), name='user-email-verify'),
	
    # url(r'^user/box/$', views.BoxListCreateView.as_view(), name='user-node-view'),
    # url(r'^user/box/(?P<identifier>([a-zA-Z0-9\_\-]+))/$', views.BoxUpdateView.as_view(), name='user-node-update'),
    # url(r'^user/box/(?P<identifier>([a-zA-Z0-9\_\-]+))/measure/$', views.MeasurementListCreateView.as_view(), name='user-node-update'),

    # url(r'^user/box/$', views.BoxListCreateView.as_view(), name='user-node-view'),


    # url(r'^staff/color/$', views.AdminColorCreateView.as_view(), name='user-node-view'),
    # url(r'^staff/color/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminColorView.as_view(), name='user-node-view'),

    url(r'^staff/pathway/$', views.AdminPathwayCreateView.as_view(), name='user-node-view'),
    url(r'^staff/pathway/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminPathwayView.as_view(), name='user-node-view'),

    # url(r'^staff/project/$', views.AdminProjectCreateView.as_view(), name='user-node-view'),
    # url(r'^staff/project/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminProjectView.as_view(), name='user-node-view'),

    # url(r'^staff/task/$', views.AdminTaskCreateView.as_view(), name='user-node-view'),
    # url(r'^staff/task/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminTaskView.as_view(), name='user-node-view'),

    # url(r'^staff/challenge/$', views.AdminChallengeCreateView.as_view(), name='user-node-view'),
    # url(r'^staff/challenge/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminChallengeView.as_view(), name='user-node-view'),

    # # url(r'^staff/tag/$', views.AdminTagCreateView.as_view(), name='user-node-view'),
    # # url(r'^staff/tag/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminTagView.as_view(), name='user-node-view'),

    # url(r'^staff/badge/$', views.AdminBadgeCreateView.as_view(), name='user-node-view'),
    # url(r'^staff/badge/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminBadgeView.as_view(), name='user-node-view'),

    url(r'^staff/student/$', views.AdminStudentCreateView.as_view(), name='user-node-view'),
    url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/$', views.AdminStudentView.as_view(), name='user-node-view'),
    url(r'^staff/student/(?P<id>([a-zA-Z0-9\_\-]+))/attendance/$', views.AdminStudentAttendanceView.as_view(), name='user-node-view'),
    
)

urlpatterns = format_suffix_patterns(urlpatterns)
