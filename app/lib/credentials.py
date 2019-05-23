import google.auth


# This is broken into its own class to make it easy to replace if you choose
# to use the Real-time enforcer docker image as a base for your own enforcer
class CredentialsBroker:

    def __init__(self):
        self.creds, _ = google.auth.default()

    # The Forseti Real-time Enforcer uses the same credentials for all api
    # calls. It sends a `project_id` kwarg for resource evaluation and
    # enforcement, so you can implement per-project credentials if you choose
    # to overwrite this class
    def get_credentials(self, **kwargs):
        return self.creds
