# -*- coding: utf-8 -*-
#
# django-ldapdb
# Copyright (c) 2009-2011, Bolloré telecom
# Copyright (c) 2013, Jeremy Lainé
# All rights reserved.
#
# See AUTHORS file for a full list of contributors.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     1. Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from django.db.models import fields, SubfieldBase

from ldapdb import escape_ldap_filter

import datetime, pytz, re


class CharField(fields.CharField):
    def __init__(self, *args, **kwargs):
        defaults = {'max_length': 200}
        defaults.update(kwargs)
        super(CharField, self).__init__(*args, **defaults)

    def from_ldap(self, value, connection):
        if len(value) == 0:
            return ''
        elif hasattr(connection, 'charset'):
            return value[0].decode(connection.charset)
        else:
            return value[0].decode('utf-8')

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        if lookup_type == 'endswith':
            return ["*%s" % escape_ldap_filter(value)]
        elif lookup_type == 'startswith':
            return ["%s*" % escape_ldap_filter(value)]
        elif lookup_type in ['contains', 'icontains']:
            return ["*%s*" % escape_ldap_filter(value)]
        elif lookup_type in ['exact', 'iexact']:
            return [escape_ldap_filter(value)]
        elif lookup_type == 'in':
            return [escape_ldap_filter(v) for v in value]

        raise TypeError("CharField has invalid lookup: %s" % lookup_type)

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        if hasattr(connection, 'charset'):
            return [value.encode(connection.charset)]
        else:
            return value

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type == 'endswith':
            return "*%s" % escape_ldap_filter(value)
        elif lookup_type == 'startswith':
            return "%s*" % escape_ldap_filter(value)
        elif lookup_type in ['contains', 'icontains']:
            return "*%s*" % escape_ldap_filter(value)
        elif lookup_type in ['exact', 'iexact']:
            return escape_ldap_filter(value)
        elif lookup_type == 'in':
            return [escape_ldap_filter(v) for v in value]

        raise TypeError("CharField has invalid lookup: %s" % lookup_type)


class PasswordField(fields.CharField):
    def __init__(self, *args, **kwargs):
        defaults = {'max_length': 200}
        defaults.update(kwargs)
        super(PasswordField, self).__init__(*args, **defaults)

    def from_ldap(self, value, connection):
        if len(value) == 0:
            return ''
        elif hasattr(connection, 'charset'):
            return value[0].decode(connection.charset)
        else:
            return value[0].decode('utf-8')

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        if lookup_type == 'endswith':
            return ["*%s" % escape_ldap_filter(value)]
        elif lookup_type == 'startswith':
            return ["%s*" % escape_ldap_filter(value)]
        elif lookup_type in ['contains', 'icontains']:
            return ["*%s*" % escape_ldap_filter(value)]
        elif lookup_type in ['exact', 'iexact']:
            return [escape_ldap_filter(value)]
        elif lookup_type == 'in':
            return [escape_ldap_filter(v) for v in value]

        raise TypeError("PasswordField has invalid lookup: %s" % lookup_type)

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        if hasattr(connection, 'charset'):
            return value.encode(connection.charset)
        else:
            return value

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type == 'endswith':
            return "*%s" % escape_ldap_filter(value)
        elif lookup_type == 'startswith':
            return "%s*" % escape_ldap_filter(value)
        elif lookup_type in ['contains', 'icontains']:
            return "*%s*" % escape_ldap_filter(value)
        elif lookup_type in ['exact', 'iexact']:
            return escape_ldap_filter(value)
        elif lookup_type == 'in':
            return [escape_ldap_filter(v) for v in value]

        raise TypeError("PasswordField has invalid lookup: %s" % lookup_type)


class ImageField(fields.Field):
    def from_ldap(self, value, connection):
        if len(value) == 0:
            return ''
        else:
            return value[0]

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        return [self.get_prep_lookup(lookup_type, value)]

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        return [value]

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        raise TypeError("ImageField has invalid lookup: %s" % lookup_type)


class IntegerField(fields.IntegerField):
    def from_ldap(self, value, connection):
        if len(value) == 0:
            return 0
        else:
            return int(value[0])

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        return [self.get_prep_lookup(lookup_type, value)]

    def get_db_prep_save(self, value, connection):
        if value is None:
            return None
        return [str(value)]

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type in ('exact', 'gte', 'lte'):
            return value
        raise TypeError("IntegerField has invalid lookup: %s" % lookup_type)


class BooleanField(fields.BooleanField):
    def from_ldap(self, value, connection):
        if len(value) == 0:
            return False
        else:
            return bool(value[0])

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        return [self.get_prep_lookup(lookup_type, value)]

    def get_db_prep_save(self, value, connection):
        if value is None:
            return None
        return [str(value)]

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type in ('exact',):
            return value
        raise TypeError("BooleanField has invalid lookup: %s" % lookup_type)


class FloatField(fields.FloatField):
    def from_ldap(self, value, connection):
        if len(value) == 0:
            return 0.0
        else:
            return float(value[0])

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        return [self.get_prep_lookup(lookup_type, value)]

    def get_db_prep_save(self, value, connection):
        if value is None:
            return None
        return [str(value)]

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type in ('exact', 'gte', 'lte'):
            return value
        raise TypeError("FloatField has invalid lookup: %s" % lookup_type)


class ListField(fields.Field):
    __metaclass__ = SubfieldBase

    def from_ldap(self, value, connection):
        return [x.decode(connection.charset) for x in value]

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        return [self.get_prep_lookup(lookup_type, value)]

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        return [x.encode(connection.charset) for x in value]

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type == 'contains':
            return escape_ldap_filter(value)
        raise TypeError("ListField has invalid lookup: %s" % lookup_type)

    def to_python(self, value):
        if not value:
            return []
        return value


class DateField(fields.DateField):
    """
    A text field containing date, in specified format.
    The format can be specified as 'format' argument, as strptime()
    format string. It defaults to ISO8601 (%Y-%m-%d).

    Note: 'lte' and 'gte' lookups are done string-wise. Therefore,
    they will onlywork correctly on Y-m-d dates with constant
    component widths.
    """

    def __init__(self, *args, **kwargs):
        if 'format' in kwargs:
            self._date_format = kwargs.pop('format')
        else:
            self._date_format = '%Y-%m-%d'
        super(DateField, self).__init__(*args, **kwargs)

    def from_ldap(self, value, connection):
        if len(value) == 0:
            return None
        else:
            return datetime.datetime.strptime(value[0],
                                              self._date_format).date()

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        return [self.get_prep_lookup(lookup_type, value)]

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        if not isinstance(value, datetime.date) \
                and not isinstance(value, datetime.datetime):
            raise ValueError(
                'DateField can be only set to a datetime.date instance')

        return [value.strftime(self._date_format)]

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type in ('exact',):
            return value
        raise TypeError("DateField has invalid lookup: %s" % lookup_type)


class DateTimeField(fields.DateTimeField):
    """
    A text field containing date, in specified format.
    The format can be specified as 'format' argument, as strptime()
    format string. It defaults to ISO8601 (%Y-%m-%d).

    Note: 'lte' and 'gte' lookups are done string-wise. Therefore,
    they will onlywork correctly on Y-m-d dates with constant
    component widths.
    """

    def __init__(self, *args, **kwargs):
        if 'format' in kwargs:
            self._date_format = kwargs.pop('format')
        else:
            self._date_format = '%Y-%m-%d %H:%M:%S'
        super(DateTimeField, self).__init__(*args, **kwargs)

    def from_ldap(self, value, connection):
        if len(value) == 0:
            return None
        else:
            return datetime.datetime.strptime(value[0],
                                              self._date_format).replace(tzinfo=pytz.utc)

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        return self.get_prep_lookup(lookup_type, value)

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        if not isinstance(value, datetime.datetime):
            raise ValueError(
                'DateTimeField can be only set to a datetime.datetime instance')

        return value.strftime(self._date_format)

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type in ('exact',):
            return value
        raise TypeError("DateTimeField has invalid lookup: %s" % lookup_type)

class GeneralizedTimeField(fields.DateTimeField):
    """
    Handle the Generalized Time format (SYNTAX OID 1.3.6.1.4.1.1466.115.121.1.24)
    In ABNF:
    GeneralizedTime = century year month day hour
                           [ minute [ second / leap-second ] ]
                           [ fraction ]
                           g-time-zone

      century = 2(%x30-39) ; "00" to "99"
      year    = 2(%x30-39) ; "00" to "99"
      month   =   ( %x30 %x31-39 ) ; "01" (January) to "09"
                / ( %x31 %x30-32 ) ; "10" to "12"
      day     =   ( %x30 %x31-39 )    ; "01" to "09"
                / ( %x31-32 %x30-39 ) ; "10" to "29"
                / ( %x33 %x30-31 )    ; "30" to "31"
      hour    = ( %x30-31 %x30-39 ) / ( %x32 %x30-33 ) ; "00" to "23"
      minute  = %x30-35 %x30-39                        ; "00" to "59"

      second      = ( %x30-35 %x30-39 ) ; "00" to "59"
      leap-second = ( %x36 %x30 )       ; "60"

      fraction        = ( DOT / COMMA ) 1*(%x30-39)
      g-time-zone     = %x5A  ; "Z"
                        / g-differential
      g-differential  = ( MINUS / PLUS ) hour [ minute ]
      MINUS           = %x2D  ; minus sign ("-")
    """
    _match_pattern = r"""
        (?P<year>[0-9]{4})			# 4 digit year
	(?P<month>(0[1-9])|(1[012]))		# 2 digit month (01-12))
	(?P<day>0[1-9]|[12][0-9]|3[01])		# 2 digit day (01-31)
	(?P<hour>[01][0-9]|2[0-3])		# 2 digit hour (00-23)
	((?P<minute>[0-5][0-9])?		# 2 digit minute (00-59)
	(?P<second>[0-5][0-9]|60)?)?		# 2 digit second/leap second (00-60)
	(?P<fraction>[,.][0-9]+)?		# Optional fractional offset
	(?P<tz>Z|[+-][0-5][0-9]([0-5][0-9])?)	# Timezone, either Z (UTC) or +/- offset
	"""

    def __init__(self, *args, **kwargs):
        if 'format' in kwargs:
            self._date_format = kwargs.pop('format')
	else:
	    self._date_format = '%Y%m%d%H%M%SZ'
        super(GeneralizedTimeField, self).__init__(*args, **kwargs)

    def from_ldap(self, value, connection):
        if len(value) == 0:
            return None
        else:
	    result = re.match(self._match_pattern, value[0], re.VERBOSE)
	    if not result:
	        return None
	    else:
	        # Build a datetime from the components
		year = int(result.group('year'))
		month = int(result.group('month'))
		day = int(result.group('day'))
		hour = int(result.group('hour'))
		fraction = 'hour'
		if result.group('minute'):
		  minute = int(result.group('minute'))
		  fraction = 'minute'
		else:
		  minute = 0;
		if result.group('second'):
		  second = int(result.group('second'))
		  fraction = 'second'
		else:
		  second = 0;
		if result.group('fraction'):
		  frac_part = result.group('fraction')[1:] # get rid of initial comma/dot
		  frac = float("0." + frac_part)
		  if fraction == 'hour':
		    mins = frac * 60
		    minute = int(mins)
		    secs = (mins - minute) * 60
		    second = int(secs)
		    micros = (secs - second) * 1000000
		    microsecond = int(micros)
		  elif fraction == 'minute':
		    secs = frac * 60
		    second = int(secs)
		    micros = (secs - second) * 1000000
		    microsecond = int(micros)
		else:
		  microsecond = 0

		tzstr = result.group('tz')
		if tzstr == 'Z':
		  tz = pytz.utc
		else:
		  sign = tzstr[0]
		  hr_part = int(tzstr[1:2])
		  mn_part = int(tzstr[3:])
		  offset = hr_part * 60 + mn_part
		  if sign == '-':
		    offset = 0 - offset
		  tz = pytz.FixedOffset(offset)

		return datetime.datetime(year, month, day, hour, minute, second, microsecond).replace(tzinfo=pytz.utc);

    def get_db_prep_lookup(self, lookup_type, value, connection,
                           prepared=False):
        "Returns field's value prepared for database lookup."
        return self.get_prep_lookup(lookup_type, value)

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        if not isinstance(value, datetime.datetime):
            raise ValueError(
                'GeneralizedTimeField can be only set to a datetime.datetime instance')

        return value.strftime(self._save_format)

    def get_prep_lookup(self, lookup_type, value):
        "Perform preliminary non-db specific lookup checks and conversions"
        if lookup_type in ('exact',):
            return value
        raise TypeError("GeneralizedTimeField has invalid lookup: %s" % lookup_type)
