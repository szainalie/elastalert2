import os
from jinja2 import Template
from texttable import Texttable
from collections import Counter

from elastalert.alerts import Alerter
from elastalert.util import elastalert_logger, lookup_es_key, EAException
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.utils import formatdate
from socket import error
from smtplib import SMTP
from smtplib import SMTP_SSL
from smtplib import SMTPAuthenticationError
from smtplib import SMTPException

class BasicMatchString(object):
    """ Creates a string containing fields in match for the given rule. """

    def __init__(self, rule, match):
        self.rule = rule
        self.match = match

    def _ensure_new_line(self):
        while self.text[-2:] != '\n\n':
            self.text += '\n'

    def _add_custom_alert_text(self):
        missing = self.rule.get('alert_missing_value', '<MISSING VALUE>')
        alert_text = str(self.rule.get('mail_alert_text', ''))
        if self.rule.get('mail_alert_text_type') == 'alert_text_jinja':
            #  Top fields are accessible via `{{field_name}}` or `{{jinja_root_name['field_name']}}`
            #  `jinja_root_name` dict is useful when accessing *fields with dots in their keys*,
            #  as Jinja treat dot as a nested field.
            template_values = self.rule | self.match
            alert_text = self.rule.get("jinja_template").render(
                template_values | {self.rule['jinja_root_name']: template_values})
        elif 'mail_alert_text_args' in self.rule:
            alert_text_args = self.rule.get('mail_alert_text_args')
            alert_text_values = [lookup_es_key(self.match, arg) for arg in alert_text_args]

            # Support referencing other top-level rule properties
            # This technically may not work if there is a top-level rule property with the same name
            # as an es result key, since it would have been matched in the lookup_es_key call above
            for i, text_value in enumerate(alert_text_values):
                if text_value is None:
                    alert_value = self.rule.get(alert_text_args[i])
                    if alert_value:
                        alert_text_values[i] = alert_value

            alert_text_values = [missing if val is None else val for val in alert_text_values]
            alert_text = alert_text.format(*alert_text_values)
        elif 'mail_alert_text_kw' in self.rule:
            kw = {}
            for name, kw_name in list(self.rule.get('mail_alert_text_kw').items()):
                val = lookup_es_key(self.match, name)

                # Support referencing other top-level rule properties
                # This technically may not work if there is a top-level rule property with the same name
                # as an es result key, since it would have been matched in the lookup_es_key call above
                if val is None:
                    val = self.rule.get(name)

                kw[kw_name] = missing if val is None else val
            alert_text = alert_text.format(**kw)

        self.text += alert_text

    def _add_rule_text(self):
        self.text += self.rule['type'].get_match_str(self.match)

    def _add_top_counts(self):
        for key, counts in list(self.match.items()):
            if key.startswith('top_events_'):
                self.text += '%s:\n' % (key[11:])
                top_events = list(counts.items())

                if not top_events:
                    self.text += 'No events found.\n'
                else:
                    top_events.sort(key=lambda x: x[1], reverse=True)
                    for term, count in top_events:
                        self.text += '%s: %s\n' % (term, count)

                self.text += '\n'

    def _add_match_items(self):
        match_items = list(self.match.items())
        match_items.sort(key=lambda x: x[0])
        for key, value in match_items:
            if key.startswith('top_events_'):
                continue
            value_str = str(value)
            value_str.replace('\\n', '\n')
            if type(value) in [list, dict]:
                try:
                    value_str = self._pretty_print_as_json(value)
                except TypeError:
                    # Non serializable object, fallback to str
                    pass
            self.text += '%s: %s\n' % (key, value_str)

    def _pretty_print_as_json(self, blob):
        try:
            return json.dumps(blob, cls=DateTimeEncoder, sort_keys=True, indent=4, ensure_ascii=False)
        except UnicodeDecodeError:
            # This blob contains non-unicode, so lets pretend it's Latin-1 to show something
            return json.dumps(blob, cls=DateTimeEncoder, sort_keys=True, indent=4, encoding='Latin-1', ensure_ascii=False)

    def __str__(self):
        self.text = ''
        if 'mail_alert_text' not in self.rule:
            self.text += self.rule['name'] + '\n\n'

        self._add_custom_alert_text()
        self._ensure_new_line()
        if self.rule.get('mail_alert_text_type') != 'alert_text_only' and self.rule.get('mail_alert_text_type') != 'alert_text_jinja':
            self._add_rule_text()
            self._ensure_new_line()
            if self.rule.get('top_count_keys'):
                self._add_top_counts()
            if self.rule.get('mail_alert_text_type') != 'exclude_fields':
                self._add_match_items()
        return self.text

class EmailAlerter(Alerter):
    """ Sends an email alert """
    required_options = frozenset(['email'])

    def __init__(self, *args):
        super(EmailAlerter, self).__init__(*args)

        self.assets_dir = self.rule.get('assets_dir', '/tmp')
        self.images_dictionary = dict(zip(self.rule.get('email_image_keys', []),  self.rule.get('email_image_values', [])))
        self.smtp_host = self.rule.get('smtp_host', 'localhost')
        self.smtp_ssl = self.rule.get('smtp_ssl', False)
        self.from_addr = self.rule.get('from_addr', 'ElastAlert')
        self.smtp_port = self.rule.get('smtp_port')
        if self.rule.get('smtp_auth_file'):
            self.get_account(self.rule['smtp_auth_file'])
        self.smtp_key_file = self.rule.get('smtp_key_file')
        self.smtp_cert_file = self.rule.get('smtp_cert_file')
        # Convert email to a list if it isn't already
        if isinstance(self.rule['email'], str):
            self.rule['email'] = [self.rule['email']]
        # If there is a cc then also convert it a list if it isn't
        cc = self.rule.get('cc')
        if cc and isinstance(cc, str):
            self.rule['cc'] = [self.rule['cc']]
        # If there is a bcc then also convert it to a list if it isn't
        bcc = self.rule.get('bcc')
        if bcc and isinstance(bcc, str):
            self.rule['bcc'] = [self.rule['bcc']]
        add_suffix = self.rule.get('email_add_domain')
        if add_suffix and not add_suffix.startswith('@'):
            self.rule['email_add_domain'] = '@' + add_suffix

    def alert(self, matches):
        if 'mail_alert_text' in self.rule:
            body = self.create_custom_alert_body(matches)
        else:
            body = self.create_alert_body(matches)

        # Add Jira ticket if it exists
        if self.pipeline is not None and 'jira_ticket' in self.pipeline:
            url = '%s/browse/%s' % (self.pipeline['jira_server'], self.pipeline['jira_ticket'])
            body += '\nJira ticket: %s' % (url)

        to_addr = self.rule['email']
        if 'email_from_field' in self.rule:
            recipient = lookup_es_key(matches[0], self.rule['email_from_field'])
            if isinstance(recipient, str):
                if '@' in recipient:
                    to_addr = [recipient]
                elif 'email_add_domain' in self.rule:
                    to_addr = [recipient + self.rule['email_add_domain']]
            elif isinstance(recipient, list):
                to_addr = recipient
                if 'email_add_domain' in self.rule:
                    to_addr = [name + self.rule['email_add_domain'] for name in to_addr]
        if self.rule.get('email_format') == 'html':
            # email_msg = MIMEText(body, 'html', _charset='UTF-8') # old way
            email_msg = MIMEMultipart()
            msgText = MIMEText(body, 'html', _charset='UTF-8')
            email_msg.attach(msgText)   # Added, and edited the previous line

            for image_key in self.images_dictionary:
                fp = open(os.path.join(self.assets_dir, self.images_dictionary[image_key]), 'rb')
                img = MIMEImage(fp.read())
                fp.close()
                img.add_header('Content-ID', '<{}>'.format(image_key))
                email_msg.attach(img)
        else:
            email_msg = MIMEText(body, _charset='UTF-8')
        email_msg['Subject'] = self.create_title(matches)
        email_msg['To'] = ', '.join(to_addr)
        email_msg['From'] = self.from_addr
        email_msg['Reply-To'] = self.rule.get('email_reply_to', email_msg['To'])
        email_msg['Date'] = formatdate()
        if self.rule.get('cc'):
            email_msg['CC'] = ','.join(self.rule['cc'])
            to_addr = to_addr + self.rule['cc']
        if self.rule.get('bcc'):
            to_addr = to_addr + self.rule['bcc']

        try:
            if self.smtp_ssl:
                if self.smtp_port:
                    self.smtp = SMTP_SSL(self.smtp_host, self.smtp_port, keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
                else:
                    # default port : 465
                    self.smtp = SMTP_SSL(self.smtp_host, keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
            else:
                if self.smtp_port:
                    self.smtp = SMTP(self.smtp_host, self.smtp_port)
                else:
                    # default port : 25
                    self.smtp = SMTP(self.smtp_host)
                self.smtp.ehlo()
                if self.smtp.has_extn('STARTTLS'):
                    self.smtp.starttls(keyfile=self.smtp_key_file, certfile=self.smtp_cert_file)
            if 'smtp_auth_file' in self.rule:
                self.smtp.login(self.user, self.password)
        except (SMTPException, error) as e:
            raise EAException("Error connecting to SMTP host: %s" % (e))
        except SMTPAuthenticationError as e:
            raise EAException("SMTP username/password rejected: %s" % (e))
        self.smtp.sendmail(self.from_addr, to_addr, email_msg.as_string())
        self.smtp.quit()

        elastalert_logger.info("Sent email to %s" % (to_addr))

    def create_default_title(self, matches):
        subject = 'ElastAlert: %s' % (self.rule['name'])

        # If the rule has a query_key, add that value plus timestamp to subject
        if 'query_key' in self.rule:
            qk = matches[0].get(self.rule['query_key'])
            if qk:
                subject += ' - %s' % (qk)

        return subject

    def get_info(self):
        return {'type': 'email',
                'recipients': self.rule['email']}

    def create_custom_alert_body(self, matches):
        body = self.get_aggregation_summary_text(matches)
        if self.rule.get('mail_alert_text_type') != 'aggregation_summary_only':
            for match in matches:
                body += str(BasicMatchString(self.rule, match))
                # Separate text of aggregated alerts with dashes
                if len(matches) > 1:
                    body += '\n----------------------------------------\n'
        return body
    
    def get_aggregation_summary_text__maximum_width(self):
        """Get maximum width allowed for summary text."""
        return 80

    def get_aggregation_summary_text(self, matches):
        text = ''
        if 'aggregation' in self.rule and 'summary_table_fields' in self.rule:
            summary_table_type = self.rule.get('summary_table_type', 'ascii')

            #Type independent prefix
            text = self.rule.get('summary_prefix', '')
            # If a prefix is set, ensure there is a newline between it and the hardcoded
            # 'Aggregation resulted in...' header below
            if text != '':
                text += "\n"

            summary_table_fields = self.rule['summary_table_fields']
            if not isinstance(summary_table_fields, list):
                summary_table_fields = [summary_table_fields]

            # Include a count aggregation so that we can see at a glance how many of each aggregation_key were encountered
            summary_table_fields_with_count = summary_table_fields + ['count']
            text += "Aggregation resulted in the following data for summary_table_fields ==> {0}:\n\n".format(
                summary_table_fields_with_count
            )

            # Prepare match_aggregation used in both table types
            match_aggregation = {}

            # Maintain an aggregate count for each unique key encountered in the aggregation period
            for match in matches:
                key_tuple = tuple([str(lookup_es_key(match, key)) for key in summary_table_fields])
                if key_tuple not in match_aggregation:
                    match_aggregation[key_tuple] = 1
                else:
                    match_aggregation[key_tuple] = match_aggregation[key_tuple] + 1

            # Limit number of rows
            if 'summary_table_max_rows' in self.rule:
                max_rows = self.rule['summary_table_max_rows']
                match_aggregation = {k:v for k, v in Counter(match_aggregation).most_common(max_rows)}

            # Type dependent table style
            if summary_table_type == 'ascii':
                text_table = Texttable(max_width=self.get_aggregation_summary_text__maximum_width())
                text_table.header(summary_table_fields_with_count)
                # Format all fields as 'text' to avoid long numbers being shown as scientific notation
                text_table.set_cols_dtype(['t' for i in summary_table_fields_with_count])

                for keys, count in match_aggregation.items():
                    text_table.add_row([key for key in keys] + [count])
                text += text_table.draw() + '\n\n'

            elif summary_table_type == 'markdown':
                # Adapted from https://github.com/codazoda/tomark/blob/master/tomark/tomark.py
                # Create table header
                text += '| ' + ' | '.join(map(str, summary_table_fields_with_count)) + ' |\n'
                # Create header separator
                text += '|-----' * len(summary_table_fields_with_count) + '|\n'
                # Create table row
                for keys, count in match_aggregation.items():
                    markdown_row = ""
                    for key in keys:
                        markdown_row += '| ' + str(key) + ' '
                    text += markdown_row + '| ' + str(count) + ' |\n'
                text += '\n'

            # max_rows message
            if 'summary_table_max_rows' in self.rule:
                text += f"Showing top {self.rule['summary_table_max_rows']} rows"
                text += "\n"

            # Type independent suffix
            text += self.rule.get('summary_suffix', '')
        return str(text)

    def create_default_title(self, matches):
        return self.rule['name']

