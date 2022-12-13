import functools
import operator
import os
from datetime import timedelta

import msgpack
import requests
from django import http
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import JsonResponse
from django.urls import reverse_lazy
from django.utils import timezone, dateparse
from django.utils.decorators import method_decorator
from django.utils.encoding import force_str
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from basiclive.core.lims.models import ActivityLog, Beamline, Container, Automounter, Data, DataType, Proposal, Group, Sample
from basiclive.core.lims.models import AnalysisReport, Project, Session
from basiclive.core.lims.templatetags.converter import humanize_duration
from basiclive.utils.data import parse_frames
from basiclive.utils.signing import Signer, InvalidSignature


if settings.LIMS_USE_SCHEDULE:
    HALF_SHIFT = int(getattr(settings, 'HOURS_PER_SHIFT', 8)/2)

PROXY_URL = getattr(settings, 'DOWNLOAD_PROXY_URL', '')
MAX_CONTAINER_DEPTH = getattr(settings, 'MAX_CONTAINER_DEPTH', 2)
LIMS_USE_PROPOSAL = getattr(settings, 'LIMS_USE_PROPOSAL', False)
LIMS_USE_CRM = getattr(settings, 'LIMS_USE_CRM', False)


def make_secure_path(path):
    # Download  key
    url = PROXY_URL + '/data/create/'
    r = requests.post(url, data={'path': path})
    if r.status_code == 200:
        key = r.json()['key']
        return key
    else:
        raise ValueError('Unable to create SecurePath')


@method_decorator(csrf_exempt, name='dispatch')
class VerificationMixin(object):
    """
    Mixin to verify identity of user.
    Requires URL parameters `username` and `signature` where the signature is a string that has been time-stamped and
    signed using a private key, and can be unsigned using the public key stored with the user's MxLIVE User object.

    If the signature cannot be successfully unsigned, or the User does not exist,
    the dispatch method will return a HttpResponseNotAllowed.
    """

    def dispatch(self, request, *args, **kwargs):
        print(kwargs)
        if not (kwargs.get('username') and kwargs.get('signature')):
            return http.HttpResponseForbidden()
        else:
            User = get_user_model()
            try:
                user = User.objects.get(username=kwargs.get('username'))
            except User.DoesNotExist:
                return http.HttpResponseNotFound()
            if not user.key:
                return http.HttpResponseBadRequest()
            else:
                try:
                    signer = Signer(public=user.key)
                    value = signer.unsign(kwargs.get('signature'))
                except InvalidSignature:
                    return http.HttpResponseForbidden()

                if value != kwargs.get('username'):
                    return http.HttpResponseForbidden()

        return super().dispatch(request, *args, **kwargs)


@method_decorator(csrf_exempt, name='dispatch')
class UpdateUserKey(View):
    """
    API for adding a public key to an MxLIVE Project. This method will only be allowed if the signature can be verified,
    and the User object does not already have a public key registered.

    :key: r'^(?P<signature>(?P<username>):.+)/project/$'
    """

    def post(self, request, *args, **kwargs):

        public = request.POST.get('public')
        signer = Signer(public=public)

        value = signer.unsign(kwargs.get('signature'))

        if value == kwargs.get('username'):
            User = get_user_model()
            modified = User.objects.filter(username=kwargs['username']).filter(Q(key__isnull=True) | Q(key='')).update(
                key=public)

            if not modified:
                return http.HttpResponseNotModified()

            ActivityLog.objects.log_activity(request, User.objects.get(username=kwargs['username']),
                                             ActivityLog.TYPE.MODIFY, 'User Key Initialized')
        else:
            return http.HttpResponseForbidden()

        return JsonResponse({})

class LaunchProposalSession(VerificationMixin, View):
    """
    Method to start an MxLIVE Session from the beamline. If a Session with the same name already exists, a new Stretch
    will be added to the Session.

    :key: r'^(?P<signature>(?P<username>):.+)/launch/(?P<beamline>)/(?P<session>)/(?P<proposal>)$'
    """

    def post(self, request, *args, **kwargs):

        project_name = kwargs.get('username')
        beamline_name = kwargs.get('beamline')
        proposal_name = kwargs.get('proposal')
        session_name = kwargs.get('session')

        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            beamline = Beamline.objects.get(acronym__exact=beamline_name)
        except Beamline.DoesNotExist:
            raise http.Http404("Beamline does not exist.")

        try:
            proposal = Proposal.objects.get(name__exact=proposal_name)
        except Proposal.DoesNotExist:
            raise http.Http404("Proposal does not exist.")
        pk = Session.objects.count() + 1
        end_time = None
        if settings.LIMS_USE_SCHEDULE:
            now = timezone.now()
            beamtime = project.beamtime.filter(beamline=beamline, start__lte=now + timedelta(hours=HALF_SHIFT),
                                               end__gte=now - timedelta(hours=HALF_SHIFT))
            if beamtime.exists():
                end_time = max(beamtime.values_list('end', flat=True)).isoformat()
            elif not beamline.active:
                end_time = (timezone.now() + timedelta(hours=2)).isoformat()
        session_name = f"EXP{pk}-" + session_name
        session, created = Session.objects.get_or_create(project=project, beamline=beamline, proposal=proposal, name=session_name)
        if created:
            # Download  key
            try:
                key = make_secure_path(os.path.join(f"prj{proposal}", "preprocessed", session.name))
                session.url = key
                session.save()
            except ValueError:
                return http.HttpResponseServerError("Unable to create SecurePath")
        session.launch()
        if created:
            ActivityLog.objects.log_activity(request, session, ActivityLog.TYPE.CREATE, 'Session launched')
        if LIMS_USE_CRM:
            feedback_url = force_str(reverse_lazy('session-feedback', kwargs={'key': session.feedback_key()}))

            session_info = {'session': session.name,
                        'duration': humanize_duration(session.total_time()),
                        'survey': request.build_absolute_uri(feedback_url),
                        'end_time': end_time}
        else:
            session_info = {'session': session.name,
                        'duration': humanize_duration(session.total_time()),
                        'end_time': end_time}
        return JsonResponse(session_info)

class LaunchSession(VerificationMixin, View):
    """
    Method to start an MxLIVE Session from the beamline. If a Session with the same name already exists, a new Stretch
    will be added to the Session.

    :key: r'^(?P<signature>(?P<username>):.+)/launch/(?P<beamline>)/(?P<session>)/$'
    """

    def post(self, request, *args, **kwargs):

        project_name = kwargs.get('username')
        beamline_name = kwargs.get('beamline')
        session_name = kwargs.get('session')
        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            beamline = Beamline.objects.get(acronym__exact=beamline_name)
        except Beamline.DoesNotExist:
            raise http.Http404("Beamline does not exist.")

        end_time = None
        if settings.LIMS_USE_SCHEDULE:
            now = timezone.now()
            beamtime = project.beamtime.filter(beamline=beamline, start__lte=now + timedelta(hours=HALF_SHIFT),
                                               end__gte=now - timedelta(hours=HALF_SHIFT))
            if beamtime.exists():
                end_time = max(beamtime.values_list('end', flat=True)).isoformat()
            elif not beamline.active:
                end_time = (timezone.now() + timedelta(hours=2)).isoformat()

        session, created = Session.objects.get_or_create(project=project, beamline=beamline, name=session_name)
        if created:
            # Download  key
            try:
                key = make_secure_path(os.path.join(project_name, session.name))
                session.url = key
                session.save()
            except ValueError:
                return http.HttpResponseServerError("Unable to create SecurePath")
        session.launch()
        if created:
            ActivityLog.objects.log_activity(request, session, ActivityLog.TYPE.CREATE, 'Session launched')

        feedback_url = force_str(reverse_lazy('session-feedback', kwargs={'key': session.feedback_key()}))

        session_info = {'session': session.name,
                        'duration': humanize_duration(session.total_time()),
                        'survey': request.build_absolute_uri(feedback_url),
                        'end_time': end_time}
        return JsonResponse(session_info)


class CloseSession(VerificationMixin, View):
    """
    Method to close an MxLIVE Session from the beamline.

    :key: r'^(?P<signature>(?P<username>):.+)/close/(?P<beamline>)/(?P<session>)/$'
    """

    def post(self, request, *args, **kwargs):

        project_name = kwargs.get('username')
        beamline_name = kwargs.get('beamline')
        session_name = kwargs.get('session')
        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            beamline = Beamline.objects.get(acronym__exact=beamline_name)
        except Beamline.DoesNotExist:
            raise http.Http404("Beamline does not exist.")

        try:
            session = project.sessions.get(beamline=beamline, name=session_name)
        except Session.DoesNotExist:
            raise http.Http404("Session does not exist.")

        session.close()
        session_info = {'session': session.name,
                        'duration': humanize_duration(session.stretches.with_duration().last().duration)}
        return JsonResponse(session_info)


KEYS = {
    'container__name': 'container',
    'container__kind__name': 'container_type',
    'group__name': 'group',
    'id': 'id',
    'name': 'name',
    'barcode': 'barcode',
    'comments': 'comments',
    'location__name': 'location',
    'port_name': 'port'
}


def prep_sample(info, **kwargs):
    sample = {
        KEYS.get(key): value
        for key, value in info.items()
    }
    sample.update(**kwargs)
    return sample

class ProposalSampleMount(VerificationMixin, View):
    """
    :param name: samplename
    :param barcode: int
    :param container: str
    :param comments: str
    :param priority: int

    :Return: sample mounted.

    :key: r'^(?P<signature>(?P<username>):.+)/samples/(?P<beamline>)/(?P<session>)$'

    """

    def post(self, request, *args, **kwargs):
        info = msgpack.loads(request.body, raw=False)

        project_name = kwargs.get('username')
        beamline_name = kwargs.get('beamline')
        session_key = kwargs.get('session')

        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            session = Session.objects.get(name__exact=session_key)
            proposal = session.proposal
        except Session.DoesNotExist:
            raise http.Http404("No session by that name.")

        try:
            beamline = Beamline.objects.get(acronym=beamline_name)
        except Beamline.DoesNotExist:
            raise http.Http404("No beamline by that name.")

        try:
            automounter = Automounter.objects.filter(beamline=beamline).select_related('container').get(active=True)
        except Automounter.DoesNotExist:
            automounter = None

        try:
            group = proposal.groups().get(group__name=info.get('name'))
        except:
            group = None

        if not automounter:
            now = timezone.now()
            one_month_ago = now - timedelta(days=30)
            container = proposal.containers.filter(status=Container.STATES.ON_SITE, modified__gte=one_month_ago).first()
        else:
            container = automounter.container


        if not group:
            group_details = {
                'name': info.get('name'),
                'proposal': proposal,
                'project': project,
                'priority': info.get('priority'),
                'comments': f"Created on the fly during {session_key}",
            }
            if container:
                group_details.update({ 'shipment': container.shipment,})
            group = Group.objects.get_or_create(**group_details)

        details = {
            'name': f"{info.get('name')}_{group.num_samples() + 1}",
            'group': group,
            'project': project,
            'priority': info.get('priority'),
            'proposal': proposal,
            'collect_status': True,
            'comments': info.get("comments", f"Created on the fly during {session_key}"),
            'barcode': info.get('barcode')
        }
        if container:
            details.update({"container": container})

        sample = Sample.objects.get_or_create(**details)
        return JsonResponse(prep_sample(sample), safe=False)



class ProjectSamples(VerificationMixin, View):
    """
    :Return: Dictionary for each On-Site sample owned by the User and NOT loaded on another beamline.

    :key: r'^(?P<signature>(?P<username>):.+)/samples/(?P<beamline>)/$'
    """

    def get(self, request, *args, **kwargs):
        project_name = kwargs.get('username')
        beamline_name = kwargs.get('beamline')

        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            beamline = Beamline.objects.get(acronym=beamline_name)
            automounter = Automounter.objects.filter(beamline = beamline).select_related('container').get(active=True)
        except (Beamline.DoesNotExist, Automounter.DoesNotExist):
            raise http.Http404("Beamline or Automounter does not exist")

        lookups = ['container__{}'.format('__'.join(['parent']*(i+1))) for i in range(MAX_CONTAINER_DEPTH)]
        query = Q(container__status=Container.STATES.ON_SITE)
        query &= (
            functools.reduce(operator.or_, [Q(**{lookup:automounter.container}) for lookup in lookups]) |
            functools.reduce(operator.and_, [Q(**{"{}__isnull".format(lookup):True}) for lookup in lookups])
        )

        sample_list = project.samples.filter(query).order_by('group__priority', 'priority').values(
            'container__name', 'container__kind__name', 'group__name', 'id', 'name', 'barcode', 'comments',
            'location__name', 'container__location__name', 'port_name'
        )
        samples = [prep_sample(sample, priority=i) for i, sample in enumerate(sample_list)]
        return JsonResponse(samples, safe=False)


TRANSFORMS = {
    'file_name': 'filename',
    'exposure_time': 'exposure',
}



class AddReport(VerificationMixin, View):
    """
    Method to add meta-data and JSON details about an AnalysisReport.

    :param username: User__username
    :param data_id: Data objects referenced
    :param score: float
    :param type: str
    :param details: JSON dict
    :param name: str
    :param beamline: Beamline__acronym
    optional:
    :param proposal: Proposal number

    :Return: {'id': < Created AnalysisReport.pk >}

    :key: r'^(?P<signature>(?P<username>):.+)/report/(?P<beamline>)/$'
    """

    def post(self, request, *args, **kwargs):
        info = msgpack.loads(request.body, raw=False)

        project_name = kwargs.get('username')
        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            data = Data.objects.filter(pk__in=info.get('data_id'))
        except:
            raise http.Http404("Data does not exist")

        #Download key
        try:
            key = make_secure_path(info.get('directory'))
        except ValueError:
            return http.HttpResponseServerError("Unable to create SecurePath")
        if LIMS_USE_PROPOSAL:
            try:
                proposal = Proposal.objects.get(name__exact=info.get('proposal'))
            except ValueError:
                raise http.Http404("Proposal does not exist")
            details = {
                'project': project,
                'score': info.get('score') if info.get('score') else 0,
                'kind': info.get('kind', 'Data Analysis'),
                'details': info.get('details'),
                'name': info.get('title'),
                'url': key,
                'proposal': proposal
            }
        else:
            details = {
                'project': project,
                'score': info.get('score') if info.get('score') else 0,
                'kind': info.get('kind', 'Data Analysis'),
                'details': info.get('details'),
                'name': info.get('title'),
                'url': key
            }
        report = AnalysisReport.objects.filter(pk=info.get('id')).first()

        if report:
            project.reports.filter(pk=report.pk).update(**details)
        else:
            report, created = AnalysisReport.objects.get_or_create(**details)

        for d in data:
            report.data.add(d)

        ActivityLog.objects.log_activity(request, report, ActivityLog.TYPE.CREATE, "{} uploaded from {}".format(
            report.name, kwargs.get('beamline', 'beamline')))
        return JsonResponse({'id': report.pk})


class AddData(VerificationMixin, View):
    """
    Method to add meta-data about Data collected on the Beamline.

    :param username: User__username
    :param data_id: If updating an existing Data object
    :param directory: Path to files
    :param energy: float (in keV)
    :param type: str (one of the acronyms defined for a Data Type)
    :param exposure: float (in seconds)
    :param attenuation: float (in percent)
    :param beam_size: float (in microns)
    :param name: str
    :param filename: filename (if single frame) or formattable template (e.g. "test_{:0>4d}.img")
    :param beamline: Beamline__acronym
    :param sample_id: If known
    :param frames: frames collected (e.g. "1-4,8,10-99"),
    :param start_time:  Starting time for data acquisition. If omitted, will be now - frames * exposure time
    :param end_time: End time for data acquisition. If omitted and start_time, is provided,
                     will be start_time + frames * exposure_time, otherwise it will be now

    :Return: {'id': < Created Data.pk >}

    :key: r'^(?P<signature>(?P<username>):.+)/data/(?P<beamline>)/$'
    """

    def post(self, request, *args, **kwargs):
        info = msgpack.loads(request.body, raw=False)

        project_name = kwargs.get('username')
        beamline_name = kwargs.get('beamline')
        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            beamline = Beamline.objects.get(acronym=beamline_name)
        except:
            raise http.Http404("Beamline does not exist")

        # Download  key
        try:
            if LIMS_USE_PROPOSAL:
                key = make_secure_path(info.get('directory') + 'raw/')
            else:
                key = make_secure_path(info.get('directory'))
        except ValueError:
            return http.HttpResponseServerError("Unable to create SecurePath")

        session = beamline.active_session()
        sample = project.samples.filter(pk=info.get('sample_id')).first()
        data = Data.objects.filter(pk=info.get('id')).first()

        if LIMS_USE_PROPOSAL:
            try:
                proposal = Proposal.objects.get(name__exact=info.get('proposal'))
            except:
                raise http.Http404("Proposal does not exist")
            details = {
                'session': (session and session.proposal == proposal) and session or None,
                'project': project,
                'proposal': proposal,
                'beamline': beamline,
                'file_name': info.get('directory'),
                'url': key,
                'sample': sample,
                'group': sample and sample.group or None,
            }
        else:
            details = {
                'session': (session and session.project == project) and session or None,
                'project': project,
                'beamline': beamline,
                'url': key,
                'sample': sample,
                'group': sample and sample.group or None,
            }

        base_fields = ['energy', 'frames', 'file_name', 'exposure_time', 'attenuation', 'name', 'beam_size']
        details.update({f: info.get(f in TRANSFORMS and TRANSFORMS[f] or f) for f in base_fields})
        details.update(kind=DataType.objects.get_by_natural_key(info['type']))
        num_frames = 1
        if info.get('frames'):
            num_frames = len(parse_frames(info['frames']))
            details.update(num_frames=num_frames)

        # Set start and end time for dataset
        end_time = timezone.now() if 'end_time' not in info else dateparse.parse_datetime(info['end_time'])
        start_time = (
            end_time - timedelta(seconds=(num_frames*info['exposure_time']))
        ) if 'start_time' not in info else dateparse.parse_datetime(info['start_time'])
        details.update(start_time=start_time, end_time=end_time)

        for k in ['sample_id', 'proposal', 'group', 'port', 'frames', 'energy', 'filename', 'exposure', 'attenuation',
                  'container', 'name', 'directory', 'type', 'id']:
            if k in info:
                info.pop(k)

        details['meta_data'] = info

        if data:
            Data.objects.filter(pk=data.pk).update(**details)
        else:
            data, created = Data.objects.get_or_create(**details)

        ActivityLog.objects.log_activity(request, data, ActivityLog.TYPE.CREATE, "{} uploaded from {}".format(
            data.kind.name, beamline.acronym))
        return JsonResponse({'id': data.pk})




class ProposalSamples(VerificationMixin, View):
    """
    :Return: Dictionary for each On-Site sample owned by the User and NOT loaded on another beamline.

    :key: r'^(?P<signature>(?P<username>):.+)/projsamples/(?<proposal>)/$'
    """

    def get(self, request, *args, **kwargs):
        project_name = kwargs.get('username')
        proposal = kwargs.get('proposal')
        active = kwargs.get('active')
        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            proposal = proposal.replace("prj", "")
            p = Proposal.objects.get(name__iexact=proposal)
            if not p.is_team_member(project):
                return http.HttpResponseForbidden()
        except Proposal.DoesNotExist:
            raise http.Http404("Proposal does not exist.")

        sample_list = p.samples.filter(collect_status=True).order_by('group__priority', 'priority').values(
            'container__name', 'container__kind__name', 'group__name', 'id', 'name', 'barcode', 'comments',

        )
        samples = [prep_sample(sample, index=i) for i, sample in enumerate(sample_list)]
        return JsonResponse(samples, safe=False)


class ProposalDataSets(VerificationMixin, View):
    """
    :Return: Dictionary for each On-Site sample owned by the User and NOT loaded on another beamline.

    :key: r'^(?P<signature>(?P<username>):.+)/dataset/(?P<sample>[\w_-]+)/(?P<kind>[\w_-]+)$'
    """

    def get(self, request, *args, **kwargs):
        project_name = kwargs.get('username')
        proposal = kwargs.get('proposal')
        sample_id = kwargs.get('sample')
        kind = kwargs.get('kind')

        try:
            project = Project.objects.get(username__exact=project_name)
        except Project.DoesNotExist:
            raise http.Http404("Project does not exist.")

        try:
            proposal = proposal.replace("prj", "")
            p = Proposal.objects.get(name__iexact=proposal)
            if not p.is_team_member(project):
                return http.HttpResponseForbidden()
        except Proposal.DoesNotExist:
            raise http.Http404("Proposal does not exist.")


        data_list = p.datasets.filter(sample_id=sample_id).order_by('end_time').values()
        samples = [prep_sample(data, priority=i) for i, data in enumerate(data_list)]
        return JsonResponse(samples, safe=False)

