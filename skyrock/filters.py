import django_filters
from django_filters import rest_framework as filters

from skyrock.models import Student, Client, Club
from skyrock.enums import Clubs, Location


class AdminStudentFilterSet(filters.FilterSet):
    clubs = django_filters.CharFilter(method='filter_clubs')
    client = django_filters.CharFilter(method='filter_client')
    birth_date = django_filters.CharFilter(method='filter_birth_date')
    identifier = django_filters.CharFilter(name='identifier')

    class Meta:
        model = Student
        fields = ('clubs', 'client' ,'birth_date','identifier',)

    def filter_clubs(self, queryset, name, value):
        print('here')
        if not value:
            return queryset

        try:
            return queryset.filter(clubs__name=Clubs(value))
        except ValueError:
            return queryset.none()

    def filter_client(self, queryset, name, value):
        if not value:
            return queryset

        try:
            return queryset.filter(client__identifier=value)
        except ValueError:
            return queryset.none()

    def filter_birth_date(self, queryset, name, value):
        if not value:
            return queryset

        try:
            return queryset.filter(birth_date__identifier=value)
        except ValueError:
            return queryset.none()

    def filter_identifier(self, queryset, name, value):
        if not value:
            return queryset

        try:
            return queryset.filter(identifier__identifier=value)
        except ValueError:
            return queryset.none()