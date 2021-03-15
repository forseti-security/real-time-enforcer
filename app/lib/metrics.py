# Copyright 2021 The Forseti Real Time Enforcer Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import socket
import time

from google.api import metric_pb2 as ga_metric
from google.cloud import monitoring_v3

from . import metadata


class Metrics:
    def __init__(self, app_name, project_id, subscription, credentials=None):
        self.app_name = app_name
        self.project_id = project_id
        self.subscription = subscription
        self.client = monitoring_v3.MetricServiceClient(credentials=credentials)

        # labels won't change during one run, so build them once
        self.metric_labels = self.build_metric_labels()

        # ensure the descriptors got created so we have descriptions
        self.create_metric_descriptors()

        # submit once on creation
        self.submit_metrics()

    def create_metric_descriptors(self):
        '''Create the metric descriptors that will be submitted.

        This is required for creating metric descriptions.  It seems that
        descriptions can be updated, but changing other fields is supposed
        to raise errors.

        '''
        self.create_pubsub_client_metric_descriptors()

    def _create_metric_descriptors(self, type_prefix, descriptors):
        '''Create metric descriptors in the cloud from a structure

        type_prefix: the prefix used to build the cloud monitoring
        metric type.  combined with the name in the descriptor to get
        the complete type.

        descriptors: a dict of dicts.  The keys are the names, used to
        fill out the type field.  The values are dicts with parameters
        for the descriptor creation.  The value dicts should specify
        metric_kind, value_type, and description.

        for example:
        type_prefix = 'custom.googleapis.com/forseti-realtime-enforcer/wooo_app'
        descriptors = {
            'count_yeah': {
                'metric_kind': ga_metric.MetricDescriptor.MetricKind.GAUGE,
                'value_type': ga_metric.MetricDescriptor.ValueType.INT64,
                'description': 'The number of yeahs currently in flight',
            },
        }

        this will produce a gauge metric of integers, with type:
        custom.googleapis.com/forseti-realtime-enforcer/wooo/count_yeah

        '''
        if not type_prefix.startswith(f'custom.googleapis.com/{self.app_name}'):
            raise ValueError(f'type_prefix must start with custom.googleapis.com/{self.app_name}/')

        if type_prefix.endswith('/'):
            raise ValueError('type_prefix must not end with a /')

        for name, d in descriptors.items():
            descriptor = ga_metric.MetricDescriptor()
            descriptor.type = f'{type_prefix}/{name}'
            for k, v in d.items():
                setattr(descriptor, k, v)

            self.client.create_metric_descriptor(
                name=f'projects/{self.project_id}',
                metric_descriptor=descriptor,
            )

    def create_pubsub_client_metric_descriptors(self):
        # for each metric, the keys must match the fields from the
        # protobuf defintions of MetricDescriptor
        descriptors = {
            'on_hold_bytes': {
                'metric_kind': ga_metric.MetricDescriptor.MetricKind.GAUGE,
                'value_type': ga_metric.MetricDescriptor.ValueType.INT64,
                'description': 'The number of bytes held by the pubsub client',
            },
            'on_hold_num': {
                'metric_kind': ga_metric.MetricDescriptor.MetricKind.GAUGE,
                'value_type': ga_metric.MetricDescriptor.ValueType.INT64,
                'description': 'The number of messages held by the pubsub client',
            },
            'load': {
                'metric_kind': ga_metric.MetricDescriptor.MetricKind.GAUGE,
                'value_type': ga_metric.MetricDescriptor.ValueType.DOUBLE,
                'description': 'The load percentage of the pubsub client',
            },
        }

        self._create_metric_descriptors(
            f'custom.googleapis.com/{self.app_name}/pubsub_client',
            descriptors,
        )

    def get_metric_data(self):
        return [
            {
                'prefix': 'pubsub_client',
                'labels': self.metric_labels,
                'data': self.get_pubsub_client_metric_values(),
            },
        ]

    def get_pubsub_client_metric_values(self):
        '''Return a dictionary with the values and types of the metrics

        Note that the kind values used in this function are from [1] and
        do not match the grpc values used in the descriptors.

        [1] https://googleapis.dev/python/monitoring/latest/monitoring_v3/types.html?highlight=monitoredresourcemetadata#google.cloud.monitoring_v3.types.TypedValue

        '''

        value = {
            'on_hold_bytes': {
                'kind': 'int64_value',
                'value': self.subscription._manager._on_hold_bytes,
            },
            'on_hold_num': {
                'kind': 'int64_value',
                'value': self.subscription._manager._messages_on_hold.size,
            },
            'load': {
                'kind': 'double_value',
                'value': self.subscription._manager.load,
            }
        }

        return value

    def build_series(self, prefix, name, labels, details):
        s = monitoring_v3.types.TimeSeries()
        s.metric.type = f'custom.googleapis.com/{self.app_name}/{prefix}/{name}'
        s.resource.type = 'generic_task'
        s.resource.labels.update(labels)

        # setup time for submissions
        now = time.time()
        seconds = int(now)
        nanos = int((now - seconds) * 10 ** 9)
        interval = monitoring_v3.TimeInterval(
            {"end_time": {"seconds": seconds, "nanos": nanos}}
        )

        # create the data point
        p = monitoring_v3.Point({
            'interval': interval,
            'value': {details['kind']: details['value']},
        })
        s.points = [p]

        return s

    def submit_metrics(self):
        series = []

        for m in self.get_metric_data():
            for name, details in m['data'].items():
                s = self.build_series(m['prefix'], name, m['labels'], details)
                series.append(s)

        if len(series) > 200:
            raise NotImplementedError('too many metrics, please implement paginated submission')

        self.client.create_time_series(request={
            'name': f'projects/{self.project_id}',
            'time_series': series,
        })

    def build_metric_labels(self):
        try:
            zone_frn = metadata.get_metadata_by_path('/instance/zone')
            zone = zone_frn.split('/')[-1]
            region = '-'.join(zone.split('-')[:-1])
        except Exception:
            region = None

        label_env_sources = {
            'project_id': 'METRICS_PROJECT_ID',
            'location': 'METRICS_LOCATION',
            'namespace': 'METRICS_NAMESPACE',
            'job': 'METRICS_JOB_NAME',
            'task_id': 'METRICS_TASK_ID',
        }

        labels = {
            'project_id': os.environ.get(
                'METRICS_PROJECT_ID',
                os.environ.get('PROJECT_ID'),
            ),
            'location': os.environ.get('METRICS_LOCATION', region),
            'namespace': os.environ.get('METRICS_NAMESPACE', self.app_name),
            'job': os.environ.get('METRICS_JOB_NAME', self.app_name),
            'task_id': os.environ.get('METRICS_TASK_ID', socket.gethostname()),
        }

        for k, v in labels.items():
            if not v:
                env_var = label_env_sources[k]
                raise ValueError(f'pubsub_client metrics could not find required value for {k}, please set env var {env_var}')

        return labels
