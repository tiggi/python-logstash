import traceback
import logging
import socket
import sys
from datetime import datetime
try:
    import json
except ImportError:
    import simplejson as json


class LogstashFormatterBase(logging.Formatter):

    def __init__(self, message_type='Logstash', tags=None, fqdn=False, log_attrs=None, extra_fields=None):
        """
        Defines base format and helper functions

        :param fqdn: Flag if host has a full qualified domain name

        :param log_attrs: list with log attributes to be added, which each one can be both
            the attribute name or a tupple containing the attribute name and the name
            to be used by logstash `(attr_name, attr_translation)`

            The list contains all the log attributes can be found at:
            http://docs.python.org/library/logging.html#logrecord-attributes

            default: ['message', ('pathname', 'path'), ('levelname', 'level'), ('name', 'logger_name')]

        :param extra_fields: dict of additional fields
        """

        if not log_attrs:
            log_attrs = ['message', ('pathname', 'path'), ('levelname', 'level'), ('name', 'logger_name')]

        self.log_attrs = []
        for attr in log_attrs:
            if type(attr) is tuple:
                self.log_attrs.append(attr)
            else:
                self.log_attrs.append((attr, attr))

        self.extra_fields = extra_fields

        self.message_type = message_type
        self.tags = tags if tags is not None else []

        if fqdn:
            self.host = socket.getfqdn()
        else:
            self.host = socket.gethostname()

    def get_log_fields(self, record):

        if sys.version_info < (3, 0):
            easy_types = (basestring, bool, dict, float, int, long, list, type(None))
        else:
            easy_types = (str, bool, dict, float, int, list, type(None))

        fields = {}

        log_keys = [attr[0] for attr in self.log_attrs]
        field_names = [attr[1] for attr in self.log_attrs]

        for key, value in record.__dict__.items():
            if key in log_keys:
                idx = log_keys.index(key)
                if isinstance(value, easy_types):
                    fields[field_names[idx]] = value
                else:
                    fields[field_names[idx]] = repr(value)

        return fields

    def get_debug_fields(self, record):

        fields = {
            'stack_trace': self.format_exception(record.exc_info),
            'lineno': record.lineno,
            'process': record.process,
            'thread_name': record.threadName,
        }

        # funcName was added in 2.5
        if not getattr(record, 'funcName', None):
            fields['funcName'] = record.funcName

        # processName was added in 2.6
        if not getattr(record, 'processName', None):
            fields['processName'] = record.processName

        # remove duplicated
        log_keys = [attr[0] for attr in self.log_attrs]
        duplicated_keys = [key for key in fields.keys() if key in log_keys]
        for key in duplicated_keys:
            del fields[key]

        return fields


    @classmethod
    def format_source(cls, message_type, host, path):
        return "%s://%s/%s" % (message_type, host, path)

    @classmethod
    def format_timestamp(cls, time):
        tstamp = datetime.utcfromtimestamp(time)
        return tstamp.strftime("%Y-%m-%dT%H:%M:%S") + ".%03d" % (tstamp.microsecond / 1000) + "Z"

    @classmethod
    def format_exception(cls, exc_info):
        return ''.join(traceback.format_exception(*exc_info)) if exc_info else ''

    @classmethod
    def serialize(cls, message):
        if sys.version_info < (3, 0):
            return json.dumps(message)
        else:
            return bytes(json.dumps(message), 'utf-8')

class LogstashFormatterVersion0(LogstashFormatterBase):
    version = 0

    def format(self, record):
        # Create message dict
        message = {
            '@timestamp': self.format_timestamp(record.created),
            '@message': record.getMessage(),
            '@source': self.format_source(self.message_type, self.host,
                                          record.pathname),
            '@source_host': self.host,
            '@source_path': record.pathname,
            '@tags': self.tags,
            '@type': self.message_type,
            '@fields': {
                'levelname': record.levelname,
                'logger': record.name,
            },
        }

        # Add log fields
        message['@fields'].update(self.get_log_fields(record))

        # Add extra fields
        if self.extra_fields:
            message['@fields'].update(self.extra_fields)

        # If exception, add debug info
        if record.exc_info:
            message['@fields'].update(self.get_debug_fields(record))

        return self.serialize(message)


class LogstashFormatterVersion1(LogstashFormatterBase):

    def format(self, record):
        # Create message dict
        message = {
            '@timestamp': self.format_timestamp(record.created),
            '@version': '1',
            'host': self.host,
            'tags': self.tags,
            'type': self.message_type,
        }

        # Add log fields
        message.update(self.get_log_fields(record))

        # Add extra fields
        if self.extra_fields:
            message.update(self.extra_fields)

        # If exception, add debug info
        if record.exc_info:
            message.update(self.get_debug_fields(record))

        return self.serialize(message)
