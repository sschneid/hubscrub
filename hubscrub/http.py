import json
import requests
from time import sleep

from hubscrub import app
from hubscrub.util import seconds_until_utc

import hubscrub.config as config


def wait_until_not_rate_limited():
    rate_limited = True

    while rate_limited:
        r = requests.get(
            'https://api.github.com/rate_limit',
            headers={'Authorization': 'token %s' % config.github_token}
        )

        if r.ok:
            rate = json.loads(r.text or r.content)

            if (rate['resources']['core']['remaining'] / rate['resources']['core']['limit']) < float(config.rate_limit_ratio):
                sleep_seconds = seconds_until_utc(rate['resources']['core']['reset']) + 1
                app.logger.debug('! rate-limited ({}/{} > {}), sleeping {} seconds until limit reset...'.format(
                    rate['resources']['core']['remaining'],
                    rate['resources']['core']['limit'],
                    float(config.rate_limit_ratio),
                    sleep_seconds
                ))

                sleep(sleep_seconds)
            else:
                rate_limited = False
        else:
            sleep_seconds = 30
            app.logger.debug('! failed to check rate limit, sleeping {} seconds before retrying...'.format(sleep_seconds))
            sleep(sleep_seconds)


def authorized_request(url, etag=None):
    wait_until_not_rate_limited()

    r = requests.get(url, headers={'Authorization': 'token %s' % config.github_token})

    if r.ok:
        if 'next' in r.links:
            link_next = r.links['next']['url']
        else:
            link_next = None

        return json.loads(r.text or r.content), link_next
    else:
        app.logger.debug('! failed to retrieve \'{}\''.format(url))
        return json.loads('{}'), None


def authorized_request_following_links(url, etag=None):
    links = [url]
    everything = []

    while links:
        data, link_next = authorized_request(links.pop())

        for d in data:
            everything.append(d)

        if link_next:
            links.append(link_next)

    return everything


def authorized_request_raw(url, etag=None):
    wait_until_not_rate_limited()

    r = requests.get(url, headers={'Authorization': 'token %s' % config.github_token})

    if r.ok:
        return r.text or r.content
    else:
        app.logger.debug('! failed to retrieve \'{}\''.format(url))
        return ''
