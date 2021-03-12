# Forseti Real-Time Enforcer

The Forseti Real-Time Enforcer uses a Stackdriver log export (to a Pub/Sub topic) to trigger policy evaluation and enforcement

[![Build Status](https://api.travis-ci.org/cleardataeng/forseti-policy-enforcer.svg?branch=master)](https://travis-ci.org/cleardataeng/forseti-policy-enforcer)

## Configuration Options

All configuration options are set as environment variables:

**PROJECT_ID:** Required, the project_id for the project that contains the Pub/Sub subscription  
**SUBSCRIPTION_NAME:** Required, the name of the Pub/Sub subscription  
**OPA_URL:** Required, The base_url for the OPA instance to use for evaluations/remediations  
**PYTHON_POLICY_PATH:** Optional, The location of python policies to use. If using the docker image you can volume mount your policies. If they require additinal packages, you should use the docker image as your base image, and perform your setup in your Dockerfile

**APP_NAME:** Optional, default=forseti-realtime-enforcer  
**ENFORCE:** Optional, default=false. Whether or not to attempt to remediate policy violations (if supported by the policy)  
**ENFORCEMENT_DELAY:** Optional, default=0. Number of seconds to delay enforcement before remediating a policy violation, useful if you use IaC tools that may get confused if resources are modified while they're operating on them.  
**STACKDRIVER_LOGGING:** Optional, default=false. Whether to use stackdriver logging versus printing to stdout  
**PER_PROJECT_LOGGING:** Optional, default=false. Whether to also send a log to the project containing the resource being evaluated or remediated. Only if STACKDRIVER_LOGGING is enabled  
**DEBUG_LOGGING:** Optional, default=false. Whether or not to include debug log messages. These can be really chatty  
**METRICS_ENABLED:** Optional, default=false.  Whether or not to submit metrics to Cloud Monitoring.  See below for details.

### Pub/Sub Customization
All of these are options, and any of these that are not set will default to the python Pub/Sub client's default values. More documentation on these can be found here: https://googleapis.dev/python/pubsub/latest/types.html

**PUBSUB_MAX_MESSAGES:** The maximum number of received - but not yet processed - messages before pausing the message stream  
**PUBSUB_MAX_BYTES:** The maximum total size of received - but not yet processed - messages before pausing the message stream  
**PUBSUB_MAX_LEASE_DURATION:** The maximum amount of time in seconds to hold a lease on a message before dropping it from the lease management  

### Cloud Monitoring Metrics

Real-Time Enforcer can optionally submit data on it's own operations
to Cloud Monitoring.  The metrics are submitted as a generic task,
using types with prefix `custom.googleapis.com/real-time-enforcer`.
The code tries to auto-discover reasonable labels, but you can control
this via these environment variables:

**METRICS_PROJECT_ID:** the project id for cloud monitoring, defaults to the value of `PROJECT_ID`.
**METRICS_LOCATION:** the location of the Real-Time Enforcer, defaults to the region discovered from the compute metadata service.
**METRICS_NAMESPACE:** a static string, defaults to `real-time-enforcer`.
**METRICS_JOB_NAME:** a static string, defaults to `real-time-enforcer`.
**METRICS_TASK_ID:** identifies individual copies of Real-Time Enforcer, defaults to the system hostname.

# Deployment example

This document will walk you through setting up a Stackdriver Log Export for your entire organization, filtering for AuditLog entries that create or update resources, and sending those log entries to a Pub/Sub topic. We will subscribe to that topic and evaluate each incoming log message and attempt to map it to a resource that [rpe-lib](https://github.com/forseti-security/resource-policy-evaluation-library) recognizes. If so, we'll evaluate it with rpe-lib against an [Open Policy Agent](https://www.openpolicyagent.org/) instance.

If you prefer to operate on a specific folder or project, the log export commands in this document should be altered appropriately.


## Prerequisites

This document assumes you have the [Google Cloud SDK](https://cloud.google.com/sdk/) installed, and the _gcloud_ binary in your _PATH_. We also assume that _gcloud_ is authenticated as a user (or serviceAccount) with the appropriate permissions.

We'll need to set some environment variables that will be used in later commands. We need the _Project ID_ of the Google project we'll be deploying cloud resources into. We also need the _Organization ID_ you wish to capture events from (See [Retrieving your Organization ID](https://cloud.google.com/resource-manager/docs/creating-managing-organization#retrieving_your_organization_id)).

```shell
# The project ID of the google project to deploy the cloud resources into
project_id='my-project-id'
organization_id='000000000000' # The numeric ID of the organization 
```

# Setting up the GCP resources

## Setting up the Stackdriver log export

First, we'll configure a log export to send specific logs to a pub/sub topic. In this example, we will export logs from the entire organization so we catch events from each project. We will filter for AuditLog entries where the severity is not `ERROR`. We're also filtering out logs from the `k8s.io` service because they're noisy, and any methodthat includes the string `delete`. You can tweak the export and filter to suit your needs.

```bash
gcloud beta logging sinks create rpe-lib-events \
  pubsub.googleapis.com/projects/$project_id/topics/rpe-lib-events \
  --organization=$organization_id \
  --include-children \
  --log-filter='’logName:”logs/cloudaudit.googleapis.com%2Factivity” severity>INFO’ 
```

## Setting up the Pub/Sub resources

We now need to create the Pub/Sub topic and subscription, and add an IAM binding to allow the log export writer to publish to the topic.

```shell
# Creating the topic
gcloud pubsub topics create rpe-lib-events --project=$project_id

# Get the writer identity for the log export
writer_id=$(gcloud logging sinks describe rpe-lib-events \
  --project=$project_id \
  --format='value(writerIdentity)'
)

# Add an IAM binding allowing the log writer to publish to our topic
gcloud alpha pubsub topics add-iam-policy-binding rpe-lib-events \
  --member=$writer_id \
  --role=roles/pubsub.publisher \
  --project=$project_id

# Create the subscription our application will use
gcloud pubsub subscriptions create rpe-lib \
  --topic rpe-lib-events \
  --project=$project_id

```

## Setting up application credentials

Our application needs access to subscribe to the Pub/Sub subscription for messages, and access to modify resources for policy enforcement. With some modification, the example script can be updated to separate credentials for the enforcement step, but for simplicity the example uses the Application Default Credentials for everything.

```shell
# Create a new service account for running the application
gcloud iam service-accounts create rpe-lib --project=$project_id

# Create a service account key and save it
gcloud iam service-accounts keys create rpe-lib_credentials.json \
  --iam-account=rpe-lib@$project_id.iam.gserviceaccount.com

# Add policy to access subscription
gcloud beta pubsub subscriptions add-iam-policy-binding rpe-lib \
  --member=serviceAccount:rpe-lib@$project_id.iam.gserviceaccount.com \
  --role=roles/pubsub.subscriber \
  --project=$project_id

# By default, logs will be printed to stdout. If you'd like to send them to stackdriver make sure to add the following permission
# You'll also need to pass the `STACKDRIVER_LOGGING` environment variable to the docker image
gcloud projects add-iam-policy-binding $project_id \
  --role=roles/logging.logWriter \
  --member=serviceAccount:rpe-lib@$project_id.iam.gserviceaccount.com

# Add policy required for enforcement
### I'm omitting this for security reasons. I recommend deciding what policies
### you wish to enforce, and research what permissions are need to enforce them
### for your organization
```

# Running OPA with our policies

We'll be using the [Open Policy Agent](https://www.openpolicyagent.org/) docker image with policies located in a folder named _policy_. You can use your own policies as long as they match the schema used by rpe-lib.

```shell
docker run -d \
  --name opa-server \
  -v $(pwd)/policy:/opt/opa/policy \
  openpolicyagent/opa \
  run --server /opt/opa/policy
```

# Building our docker image

The enforcement code is all in the `run.py` script in this directory. Stackdriver logs are parsed in `stackdriver.py` which attempts to extract the data we need to find a resource in the Google APIs. After we identify the resource we pass it to rpe-lib and iterate over the violations, remediating them one-at-a-time.

A public docker image is available on dockerhub which you can use as-is if it suits your needs. Otherwise you can alter the code either run it directly or build your own container image to run.

The docker image is based on the `python:slim` image, and can be built using the following command:

```shell
docker build -t forseti-policy-enforcer .
```


# Running our application

This example uses the public image from Dockerhub, and should be altered if you chose to build your own image:

```shell
docker run -ti --rm \
    --link opa-server \
    -e PROJECT_ID=$project_id \
    -e SUBSCRIPTION_NAME=rpe-lib \
    -e OPA_URL="http://opa-server:8181/v1/data" \
    -e ENFORCE=true \
    -e STACKDRIVER_LOGGING=false \
    -e GOOGLE_APPLICATION_CREDENTIALS=/opt/rpe-lib/etc/credentials.json \
    -v <path_to_credentials_file>:/opt/rpe-lib/etc/credentials.json \
    forsetisecurity/forseti-policy-enforcer
```

## Adding resources from Stackdriver
Add your resource type to the StackdriverLogParser [_extract_asset_info()](https://github.com/forseti-security/real-time-enforcer/blob/8531f53abd3a1ca02af6c2b852a8cc6a188987e1/app/parsers/stackdriver.py#L126) 
function in order to filter for the correct AuditLog resource type message and 
return relevant data about the resource that can be parsed.

Below is an example that adds the `gke_nodepool` resource type, which returns a 
dictionary, “resource_data”, that contains the user relevant properties from 
the AuditLog of a `gke_nodepool` resource.

```       
elif res_type == "gke_nodepool":
            resource_data = {
                'resource_type': 'container.projects.locations.clusters.nodePools',
                'cluster': prop("resource.labels.cluster_name"),
                'name': prop("resource.labels.nodepool_name"),
                'project_id': prop("resource.labels.project_id"),
                'location': prop("resource.labels.location"),
            }
            add_resource()
```

Each resource that is then returned is evaluated against the list of available 
policies and enforced if violations are found. These policies can be found in 
the [resource-policy-evaluation-library Github repository](https://github.com/forseti-security/resource-policy-evaluation-library). 
Refer to the Adding resources and policies for evaluation section there for 
documentation on how to add new resources and policies for evaluation.

# Customization

Real-time enforcer can be customized by replacing some components via volume mounts, or by building a new Docker image based on the public one. Below are some examples

## Customizing an evaluation

After running evaluations, we pass each evaluation through the `app.lib.hooks.process_evaluation` function. That function is also passed the ParsedMessage object (or the trigger for the evaluation). So if you'd like to perform some pre-processing on the evaluation, you can simply replace that function. Lets say you have defined your own function as follows:

```python
# file: evaluation_hook.py

# An example evaluation hook that includes some possible uses
def process_evaluation(evaluation, trigger):
    r = evaluation.resource

    # Mark all evaluations for my-exempt-project as excluded from enforcement
    if r.project_id = 'my-exempt-project':
        evaluation.excluded = True

    # Mark all test resources as excluded from enforcement
    if r.labels.get('environment') == 'test':
        evaluation.excluded = True

    # log some extra data for a specific policy
    if evaluation.policy_id == 'compute_instances_fake_policy':
        print('some log message')

```

You can then run the docker image with that file mounted via `docker run -v /path/to/evaluation_hook.py:/app/hooks/evaluation.py [...] forsetisecurity/real-time-enforcer:v1.0.12`

## Customizing the enforcement decision

Several things factor into whether or not a policy should be enforced (ex: app-level enforcement toggle, is the evaluation compliant or excluded, etc). Real-time enforcer also calls `apps.lib.hooks.process_enforcement_decision` which can be overridden in the same way as an evaluation.

```python
# file: enforcement_hook.py

# An example enforcement hook
def process_enforcement_decision(decision, trigger):
    r = decision.evaluation.resource

    # Prevent enforcement on a specific project
    if r.project_id == 'my-no-enforcement-project':
        decision.cancel('this project has enforcement disabled')
```
