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

from app.lib.stackdriver import StackdriverParser


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
    ("app-engine-debug.json", "apps.services.versions.instances", "write", "apps/my_project/services/default/versions/test-instance/instances/aef-default-test-instance"),
    ("bq-ds-set-iam-policy.json", "bigquery.datasets", "write", "wooo"),
    ("pubsub-subscription-set-iam-policy.json", "pubsub.projects.subscriptions.iam", "write", "test-subscription"),
    ("pubsub-topic-set-iam-policy.json", "pubsub.projects.topics.iam", "write", "test-topic"),

    # CloudSQL logs are inconsistent. See https://issuetracker.google.com/issues/137629452
    ("cloudsql-resource.labels.json", "sqladmin.instances", "write", "test-instance"),
    ("cloudsql-protoPayload.request.body.json", "sqladmin.instances", "write", "test-instance"),
    ("cloudsql-protoPayload.request.resource.instanceName.instanceId.json", "sqladmin.instances", "write", "test-instance"),
    ("cloudfunctions-set-iam-policy.json", "cloudfunctions.projects.locations.functions.iam", "write", "example_function"),
    ("compute-subnetworks-enable-flow-logs.json", "compute.subnetworks", "write", "example"),
    ("compute-subnetworks-set-private-ip-google-access.json", "compute.subnetworks", "write", "example"),
    ("compute-firewalls-enable-logs-policy.json", "compute.firewalls", "write", "test-firewall"),
    ("dataproc_createcluster.json", "dataproc.clusters", "write", "test-dataproc-cluster")
    ("gke-cluster-update.json", "container.projects.locations.clusters", "write", "example-cluster"),
    ("gke-nodepool-set.json", "container.projects.locations.clusters.nodePools", "write", "example-cluster/nodePools/example-pool")
]

@pytest.mark.parametrize(
    "filename,expected_resource_type,expected_operation_type,expected_resource_name",
    test_single_asset_log_params
)
def test_single_asset_log_messages(filename, expected_resource_type, expected_operation_type, expected_resource_name):
    log_message = get_test_data(filename)

    assets = StackdriverParser.get_assets(log_message)
    assert len(assets) == 1
    asset_info = assets[0]

    assert asset_info['resource_type'] == expected_resource_type
    assert asset_info['operation_type'] == expected_operation_type
    assert asset_info['resource_name'] == expected_resource_name
