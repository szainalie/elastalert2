from elastalert.alerts import Alerter, BasicMatchString
class ClickupAlerter(Alerter):
    """ Creates a Clickup task for each alert """
    required_options = frozenset(['clickup_task_id', 'clickup_token'])
    def __init__(self, rule):
        super(ClickupAlerter, self).__init__(rule)
        self.clickup_task_id = self.rule.get('clickup_task_id')
        self.clickup_token = self.rule.get('clickup_token')
    def alert(self, matches):
        for match in matches:
            match_string = BasicMatchString(self.rule, match)
            self.create_clickup_comment(match_string)
    
    def get_info(self):
        return {'type': 'clickup',
                'clickup_task_id': self.clickup_task_id}
    def create_clickup_comment(self, match_string):
        """ Creates a comment on a Clickup task using a match string """
        import requests
        import json
        comment = '{0} {1}'.format(self.rule['name'], match_string)
        url = 'https://api.clickup.com/api/v1/task/{0}/comment'.format(self.clickup_task_id)
        headers = {'content-type': 'application/json', 'Authorization': self.clickup_token}
        data = {'comment': comment}
        response = requests.post(url, data=json.dumps(data), headers=headers)
        if response.status_code != 201:
            raise EAException("Error posting to Clickup: {0}".format(response.text))
