import json
import os

from stackdriver import StackdriverParser


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

    asset_info = StackdriverParser.get_asset(bqds)
    assert asset_info is not None

    expected = {
        'resource_type': 'bigquery.datasets',
        'resource_name': 'wooo',
        'resource_location': '',
        'project_id': 'fake-project',
        'method_name': 'google.iam.v1.IAMPolicy.SetIamPolicy',
        'operation_type': 'write',
    }
    assert asset_info == expected
