# Copyright 2019 The Forseti Real Time Enforcer Authors. All rights reserved.
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


import json
import os
import pytest

from app.parsers.stackdriver import StackdriverParser
from google.oauth2.credentials import Credentials
from rpe.resources.gcp import GoogleAPIResource, GcpComputeDisk

test_google_args = {
    'credentials': Credentials(token='bogus'),
}


def get_test_data(filename):
    '''Load json data from the tests dir'''
    p = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        'data',
        filename,
    )

    with open(p) as f:
        return json.load(f)

# parameters for testing logs that should return a single asset
test_single_asset_log_params = [
    # filename, expected_resource_type, expected_operation_type, expected_resource_name
    ("app-engine-debug.json", "appengine.googleapis.com/Instance", "write", "aef-default-test-instance"),
    ("bq-ds-set-iam-policy.json", "bigquery.googleapis.com/Dataset", "write", "wooo"),
    ("bigtable-set-iam-policy.json", "bigtableadmin.googleapis.com/Instance", "write", "example-instance"),
    ("pubsub-subscription-set-iam-policy.json", "pubsub.googleapis.com/Subscription", "write", "test-subscription"),
    ("pubsub-topic-set-iam-policy.json", "pubsub.googleapis.com/Topic", "write", "test-topic"),

    # CloudSQL logs are inconsistent. See https://issuetracker.google.com/issues/137629452
    ("cloudsql-resource.labels.json", "sqladmin.googleapis.com/Instance", "write", "test-instance"),
    ("cloudsql-protoPayload.request.body.json", "sqladmin.googleapis.com/Instance", "write", "test-instance"),
    ("cloudsql-protoPayload.request.resource.instanceName.instanceId.json", "sqladmin.googleapis.com/Instance", "write", "test-instance"),
    ("cloudfunctions-set-iam-policy.json", "cloudfunctions.googleapis.com/CloudFunction", "write", "example_function"),
    ("compute_networks_insert_1.json", "compute.googleapis.com/Network", "write", "xyz"),
    ("compute_networks_insert_2.json", "compute.googleapis.com/Network", "write", "xyzcli"),
    ("compute_networks_insert_3.json", "compute.googleapis.com/Network", "write", "datalab-network"),
    ("compute-subnetworks-enable-flow-logs.json", "compute.googleapis.com/Subnetwork", "write", "example"),
    ("compute-subnetworks-set-private-ip-google-access.json", "compute.googleapis.com/Subnetwork", "write", "example"),
    ("compute-firewalls-enable-logs-policy.json", "compute.googleapis.com/Firewall", "write", "test-firewall"),
    ("dataproc_createcluster.json", "dataproc.googleapis.com/Cluster", "write", "test-dataproc-cluster"),
    ("datafusion-create-instance.json", "datafusion.googleapis.com/Instance", "create", "test-instance"),
    ("datafusion-update-instance.json", "datafusion.googleapis.com/Instance", "write", "test-instance"),
    ("gke-cluster-update.json", "container.googleapis.com/Cluster", "write", "example-cluster"),
    ("gke-nodepool-set.json", "container.googleapis.com/NodePool", "write", "example-pool"),

    ("servicemanagement-enable-service.json", "serviceusage.googleapis.com/Service", "write", "youtubeadsreach.googleapis.com"),
    ("servicemanagement-disable-service.json", "serviceusage.googleapis.com/Service", "write", "youtubereporting.googleapis.com"),
    ("servicemanagement-activate-service.json", "serviceusage.googleapis.com/Service", "write", "calendar-json.googleapis.com"),
    ("servicemanagement-deactivate-service.json", "serviceusage.googleapis.com/Service", "write", "zync.googleapis.com"),
    ("serviceusage-enable.json", "serviceusage.googleapis.com/Service", "write", "youtubereporting.googleapis.com"),
    ("serviceusage-disable.json", "serviceusage.googleapis.com/Service", "write", "zync.googleapis.com"),
    ("dataflow-job-step.json", "dataflow.googleapis.com/Job", "write", "job-id"),
    ("memorystore-redis.json", "redis.googleapis.com/Instance", "write", "test-instance"),

]

test_log_resource_count_params = [
    ("serviceusage-batchenable.json", 3),
    ("compute-hardened-images.json", 3),
]

@pytest.mark.parametrize(
    "filename,expected_resource_type,expected_operation_type,expected_resource_name",
    test_single_asset_log_params
)
def test_single_asset_log_messages(filename, expected_resource_type, expected_operation_type, expected_resource_name):
    log_message = get_test_data(filename)

    assets = StackdriverParser._extract_asset_info(log_message)
    assert len(assets) == 1
    asset_info = assets[0]

    assert asset_info['resource_type'] == expected_resource_type
    #assert asset_info['operation_type'] == expected_operation_type
    assert asset_info['name'] == expected_resource_name

@pytest.mark.parametrize(
    "filename,expected_resource_type,expected_operation_type,expected_resource_name",
    test_single_asset_log_params
)
def test_rpe_from_stackdriver_data(filename, expected_resource_type, expected_operation_type, expected_resource_name):
    log_message = get_test_data(filename)

    assets = StackdriverParser._extract_asset_info(log_message)
    asset_info = assets[0]

    GoogleAPIResource.from_resource_data(client_kwargs=test_google_args, **asset_info)

@pytest.mark.parametrize(
    "filename,expected_resource_count",
    test_log_resource_count_params
)
def test_log_resource_count(filename, expected_resource_count):
    log_message = get_test_data(filename)

    assets = StackdriverParser._extract_asset_info(log_message)
    assert len(assets) == expected_resource_count
    asset_info = assets[0]

@pytest.mark.parametrize(
    'filename,expected_disk_names',
    [
        ('compute_instance_creation_logs_1.json', ['console-devicenames', 'disk2name']),
        ('compute_instance_creation_logs_2.json', []),
        ('compute_instance_creation_logs_3.json', ['console-nochange']),
        ('compute_instance_creation_logs_4.json', ['gcloud-devicename-mismatch']),
        ('compute_instance_creation_logs_5.json', ['demo-testing-good-boot', 'demo-testing-good-data']),
    ]

)
def test_compute_instance_logs_get_disk_names(filename, expected_disk_names):
    '''
        Instance creation audit logs contain details about the disks, but extracting the disk name is
        complicated. This tests multiple known log formats for instance creation against expected disk names.
    '''

    log = get_test_data(filename)

    assets = StackdriverParser._extract_asset_info(log)

    disk_names = [asset['name'] for asset in assets if asset['resource_type'] == GcpComputeDisk.resource_type]
    assert sorted(disk_names) == sorted(expected_disk_names)
