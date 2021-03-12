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

from urllib import request


def get_metadata_by_path(path, version='v1'):
    url = f'http://metadata.google.internal/computeMetadata/{version}{path}'
    headers = {'Metadata-Flavor': 'Google'}
    req = request.Request(url, method='GET', headers=headers)

    with request.urlopen(req) as resp:
        return resp.read().decode('utf-8')
