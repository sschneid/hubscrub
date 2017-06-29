import pypd
from hubscrub import app
import hubscrub.config as config


def pagerduty_alert(summary, severity='critical', source='hubscrub', dedup_key=None):
    if config.pagerduty_service_key is not None:
        try:
            pypd.EventV2.create(data={
                'routing_key': config.pagerduty_service_key,
                'event_action': 'trigger',
                'dedup_key': dedup_key,
                'payload': {
                    'summary': summary,
                    'severity': severity,
                    'source': source,
                }
            })
        except:
            app.logger.debug('      ! failed to create PagerDuty alert')
