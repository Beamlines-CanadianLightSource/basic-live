from django.contrib import admin
from basiclive.core.lims import models
from django.conf import settings
LIMS_USE_PROPOSAL = getattr(settings, 'LIMS_USE_PROPOSAL', False)


class ProjectAdmin(admin.ModelAdmin):
    if LIMS_USE_PROPOSAL:
        list_display = ('identity', 'name', 'proposal', 'project')
        search_fields = ('name', 'proposal__name')
    else:
        list_display = ('identity', 'project')
        search_fields = ('name', 'project__username')


class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'contact_person', 'email')
    search_fields = ('username', 'contact_person')

class LocationAdmin(admin.ModelAdmin):
    list_filter = ('kind',)

admin.site.register(models.Guide)
admin.site.register(models.Beamline)
admin.site.register(models.Carrier)
admin.site.register(models.Automounter, ProjectAdmin)
admin.site.register(models.ProjectType)
admin.site.register(models.ProjectDesignation)
admin.site.register(models.Project, UserAdmin)
admin.site.register(models.ComponentType)
admin.site.register(models.RequestType)
admin.site.register(models.DataType)
admin.site.register(models.ContainerType)
admin.site.register(models.ContainerLocation, LocationAdmin)

admin.site.register(models.Shipment, ProjectAdmin)
admin.site.register(models.Container, ProjectAdmin)
admin.site.register(models.Group, ProjectAdmin)
admin.site.register(models.Sample, ProjectAdmin)
admin.site.register(models.Request, ProjectAdmin)
admin.site.register(models.Data, ProjectAdmin)
admin.site.register(models.AnalysisReport, ProjectAdmin)
admin.site.register(models.Session, ProjectAdmin)
