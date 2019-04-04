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


def test_bq_ds_iam_policy_update():
    bqds = get_test_data('bq-ds-set-iam-policy.json')

    assets = StackdriverParser.get_assets(bqds)
    assert len(assets) == 1
    asset_info = assets[0]

    expected = {
        'resource_type': 'bigquery.datasets',
        'resource_name': 'wooo',
        'resource_location': '',
        'project_id': 'fake-project',
        'method_name': 'google.iam.v1.IAMPolicy.SetIamPolicy',
        'operation_type': 'write',
    }
    assert asset_info == expected
