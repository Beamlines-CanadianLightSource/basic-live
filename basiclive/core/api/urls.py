from django.urls import re_path as url
from django.conf import settings
from . import views


def keyed_url(regex, view, kwargs=None, name=None):
    regex = (r'(?P<signature>(?P<username>[\w_-]+):.+)/') + regex[1:]
    return url(regex, view, kwargs, name)


urlpatterns = [
    keyed_url(r'^data/(?P<beamline>[\w_-]+)/$', views.AddData.as_view()),
    keyed_url(r'^report/(?P<beamline>[\w_-]+)/$', views.AddReport.as_view()),

    keyed_url(r'^project/$', views.UpdateUserKey.as_view(), name='project-update'),
    keyed_url(r'^samples/(?P<beamline>[\w_-]+)/$', views.ProjectSamples.as_view(), name='project-samples'),
    keyed_url(r'^close/(?P<beamline>[\w_-]+)/(?P<session>[\w_-]+)/$', views.CloseSession.as_view(), name='session-close'),
]


if settings.LIMS_USE_PROPOSAL:
    keyed_url(r'^propsamples/(?P<proposal>[\w_-]+)/$', views.ProposalSamples.as_view(), name='proposal-samples'),
    keyed_url(r'^propdata/(?P<proposal>[\w_-]+)/(?P<sample>[\w_-]+)/(?P<kind>[\w_-]+)/$', views.ProposalDataSets.as_view(), name='proposal-dataset')
    urlpatterns += [keyed_url(r'^launch/(?P<beamline>[\w_-]+)/(?P<session>[\w_-]+)/(?P<proposal>[\w_-]+)/$',
                              views.LaunchProposalSession.as_view(), name='session-launch'),
                    keyed_url(r'^samples/(?P<beamline>[\w_-]+)/(?P<session>[\w_-]+)//$',
                              views.ProposalSampleMount.as_view(), name='sample-mount')
                    ]
else:
    urlpatterns += [keyed_url(r'^launch/(?P<beamline>[\w_-]+)/(?P<session>[\w_-]+)/$', views.LaunchSession.as_view(), name='session-launch'),
]