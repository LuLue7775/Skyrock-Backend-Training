from django.db import models
from rest_framework import serializers
from datetime import datetime, timezone

class MoneyField(models.DecimalField):
    """
    Decimal Field with hardcoded precision of 28 and a scale of 18.

    Usage:
    from decimal import Decimal
    field_name = MoneyField(default=Decimal(0))
    """

    def __init__(self, verbose_name=None, name=None, max_digits=28,
                 decimal_places=18, **kwargs):
        super(MoneyField, self).__init__(verbose_name, name, max_digits,
            decimal_places, **kwargs)


class TimestampField(serializers.Field):
    """
    Handles the serialization of datetime to timestamps.
    """

    def __init__(self, *args, **kwargs):
        self.multiplier = kwargs.pop('multiplier', 1000)
        super().__init__(*args, **kwargs)

    def to_representation(self, obj):
        try:
            return int(obj.timestamp() * self.multiplier)
        except AttributeError:
            return None

    def to_internal_value(self, obj):
        dt = datetime.strptime(str(obj), '%Y-%m-%dT%H:%M:%SZ').timestamp()
        obj = datetime.fromtimestamp(int(dt))
        return obj
