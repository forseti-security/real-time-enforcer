# Example: Using a Stackdriver log export to trigger policy evaluation and enforcement

This document will walk you through setting up a Stackdriver Log Export for your entire organization, filtering for AuditLog entries that create or update resources, and sending those log entries to a Pub/Sub topic. We will subscribe to that topic and evaluate each incoming log message and attempt to map it to a resource that *Micromanager* recognizes. If so, we'll evaluate it with micromanager and any configured policy engines.

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

First, we'll configure a log export to send specific logs to a pub/sub topic. In this example, we will export logs from the entire organization so we catch events from each project. We will filter for AuditLog entries where the severity is not `ERROR`. You can tweak the export and filter to suit your needs.

```bash
gcloud beta logging sinks create micromanager-events \
  pubsub.googleapis.com/projects/$project_id/topics/micromanager-events
  --organization=$organization_id \
  --include-children \
  --log-filter='protoPayload."@type"="type.googleapis.com/google.cloud.audit.AuditLog" severity!="ERROR"'
```

## Setting up the Pub/Sub resources

We now need to create the Pub/Sub topic and subscription, and add an IAM binding to allow the log export writer to publish to the topic.

```shell
# Creating the topic
gcloud pubsub topics create micromanager-events --project=$project_id

# Get the writer identity for the log export
writer_id=$(gcloud logging sinks describe micromanager-events \
  --project=$project_id \
  --format='value(writerIdentity)'
)

# Add an IAM binding allowing the log writer to publish to our topic
gcloud alpha pubsub topics add-iam-policy-binding micromanager-events \
  --member=$writer_id \
  --role=roles/pubsub.publisher \
  --project=$project_id

# Create the subscription our application will use
gcloud pubsub subscriptions create micromanager \
  --topic micromanager-events \
  --project=$project_id

```

## Setting up application credentials

Our application needs access to subscribe to the Pub/Sub subscription for messages, and access to modify resources for policy enforcement. With some modification, the example script can be updated to separate credentials for the enforcement step, but for simplicity the example uses the Application Default Credentials for everything.

```shell
# Create a new service account for running the application
gcloud iam service-accounts create micromanager --project=$project_id

# Create a service account key and save it
gcloud iam service-accounts keys create micromanager_credentials.json \
  --iam-account=micromanager@$project_id.iam.gserviceaccount.com

# Add policy to access subscription
gcloud beta pubsub subscriptions add-iam-policy-binding micromanager \
  --member=serviceAccount:micromanager@$project_id.iam.gserviceaccount.com \
  --role=roles/pubsub.subscriber \
  --project=$project_id

# Add policy required for enforcement
### I'm omitting this for security reasons. I recommend deciding what policies
### you wish to enforce, and research what permissions are need to enforce them
### for your organization
```

# Running OPA with our policies

We'll be using the [Open Policy Agent](https://www.openpolicyagent.org/) docker image with policies located in a folder named _policy_. You can use your own policies as long as they match the schema used by Micromanager.

```shell
docker run -d \
  --name opa-server \
  -v $(pwd)/policy:/opt/opa/policy \
  openpolicyagent/opa \
  run --server /opt/opa/policy
```

# Building our docker image

The code is all in the `run.py` script in this directory. The majority of the code is just normalizing the Stackdrive AuditLog messages into a standard format that we can use to find the resource in the google API. After we identify the resource we pass it to micromanager and iterate over the violations, remediating them one-at-a-time.

A public docker image is available on dockerhub which you can use as-is if it suits your needs. Otherwise you can alter the code either run it directly or build your own container image to run.

The docker image is based on the `python:slim` image, and can be built using the following command:

```shell
docker build -t micromanager .
```


# Running our application

This example uses the public image from Dockerhub, and should be altered if you chose to build your own image:

```shell
docker run -ti --rm \
    --link opa-server
    -e PROJECT_ID=$project_id \
    -e SUBSCRIPTION_NAME=micromanager \
    -e OPA_URL="http://opa-server:8181/v1/data" \
    -e GOOGLE_APPLICATION_CREDENTIALS=/opt/micromanager/etc/credentials.json \
    -v <path_to_credentials_file>:/opt/micromanager/etc/credentials.json \
    cleardata/micromanager:stackdriver-pubsub
```
