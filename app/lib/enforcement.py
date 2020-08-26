class EnforcementDecision:

    def __init__(self, evaluation, trigger):
        self.evaluation = evaluation
        self.trigger = trigger
        self.enforce = True
        self.reasons = []

        self.initial_decision()

    def initial_decision(self):

        # Do we need to
        if self.evaluation.compliant:
            self.cancel('is_compliant')

        # Is it excluded from enforcement
        if self.evaluation.excluded:
            self.cancel('is_excluded')

        # Can we
        if not self.evaluation.remediable:
            self.cancel('is_not_remediable')

        # Does the trigger indicate we shouldn't
        if not self.trigger.control_data.enforce:
            self.cancel('trigger_disabled')

    def cancel(self, reason):
        self.enforce = False
        self.reasons.append(reason)


