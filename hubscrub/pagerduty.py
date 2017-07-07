from time import sleep, time

from hubscrub import app, health
from hubscrub.redis import init_redis_client

import hubscrub.config as config

import pypd


redis_client = init_redis_client()


def pagerduty_alert(summary, severity='critical', source='hubscrub', dedup_key=None):
    try:
        pypd.EventV2.create(data={
            'routing_key': config.pagerduty_service_key,
            'event_action': 'trigger',
            'dedup_key': dedup_key,
            'payload': {
                'summary': summary,
                'severity': severity,
                'source': source
            }
        })
    except:
        app.logger.debug('! failed to create PagerDuty alert')


def vulnerability_paging_scan():
    global redis_client
    health['pagerduty_scan_start'] = time()
    try:
        redis_client.ping()
    except:
        redis_client = init_redis_client()

    redis_client.set('pagerduty_scan_in_progress', '1')
    redis_client.expire('pagerduty_scan_in_progress', int(config.scan_ttl))

    for vuln in redis_client.scan_iter(match='vuln_*'):
        data = redis_client.hgetall(vuln)
        if 'approved'not in data:
            if (float(time()) - float(data['discovered']) > int(config.pagerduty_alert_interval)):
                if 'triggered_page' not in data:
                    pagerduty_alert('{} leaked {} - {}/vulnerability/{}'.format(
                        data['member'],
                        data['fingerprint'],
                        config.hubscrub_url,
                        data['id']
                    ),
                    dedup_key=data['id'])

                    redis_client.hset(vuln, 'triggered_page', '1')

    redis_client.delete('pagerduty_scan_in_progress')


def periodic_scan():
    global redis_client
    while True:
        health['pagerduty_scan_event_loop'] = time()
        try:
            redis_client.ping()
        except:
            redis_client = init_redis_client()

        if redis_client.exists('pagerduty_scan_in_progress'):
            app.logger.debug('! would launch period page scan, but page scan already in progress')
        else:
            try:
                vulnerability_paging_scan()
            except:
                break

        sleep(60)
