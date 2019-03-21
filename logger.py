import pprint
import google.cloud.logging


class Logger:


    ''' Log to console or stackdriver '''

    def __init__(self, log_name, stackdriver=False, project_id=None, credentials=None): 

        self.stackdriver = stackdriver

        if stackdriver:
            client = google.cloud.logging.Client(project=project_id, credentials=credentials)
            self.sd_logger = client.logger(log_name)


    def __call__(self, data):
        if self.stackdriver:
            if isinstance(data, dict):
                self.sd_logger.log_struct(data)
            else:
                self.sd_logger.log_text(data)

        else:
            if isinstance(data, dict):
                pprint.pprint(data)
            else:
                print(data)
