import json
import re
from time import sleep, time
from threading import Thread

from hubscrub import app
from hubscrub.http import authorized_request, authorized_request_following_links, authorized_request_raw
from hubscrub.redis import init_redis_client
from hubscrub.slack import slack_alert
from hubscrub.pagerduty import pagerduty_alert

import hubscrub.config as config


redis_client = init_redis_client()


def get_organization_members(organization):
    return authorized_request_following_links('https://api.github.com/orgs/{}/members'.format(organization))


def get_member_events(member):
    return authorized_request_following_links('https://api.github.com/users/{}/events'.format(member))


def get_member_gists(member):
    return authorized_request_following_links('https://api.github.com/users/{}/gists'.format(member))


def github_commit_scan(member, fingerprints):
    global redis_client
    try:
        redis_client.ping()
    except:
        redis_client = init_redis_client()

    events = get_member_events(member)
    event_count = 0

    # Scan member events for code pushes
    for event in events:
        if event['type'] == 'PushEvent':
            event_count += 1

            for event_commit in event['payload']['commits']:
                if not redis_client.exists('commit_{}'.format(event_commit['sha'])):
                    app.logger.debug('  - scanning commit {}:{}...'.format(
                        event['repo']['name'],
                        event_commit['sha'][:6]
                    ))

                    try:
                        commit, link_next = authorized_request(event_commit['url'])
                    except:
                        app.logger.debug('    ! link not found')

                        # Commit likely deleted from history, mark as scanned
                        redis_client.set('commit_{}'.format(event_commit['sha']), '1')
                        break

                    # Scan each file patchset
                    if 'files' in commit:
                        file_count = 0

                        for commit_file in commit['files']:
                            if 'patch' in commit_file:
                                file_count += 1

                                app.logger.debug('    - scanning patchset to {}...'.format(commit_file['filename']))
                                for to_match in fingerprints['fingerprints']:
                                    to_match_regex = fingerprints['fingerprints'][to_match]
                                    match_pattern = re.compile(to_match_regex, re.IGNORECASE)
                                    if match_pattern.search(commit_file['patch']):
                                        app.logger.debug('      ! {} matched {}'.format(
                                            commit_file['filename'], to_match))

                                        vuln_id = 'vuln_{}_{}'.format(event_commit['sha'], file_count)

                                        if redis_client.exists(vuln_id):
                                            break

                                        redis_client.hmset(vuln_id, {
                                            'id': vuln_id,
                                            'sha': event_commit['sha'],
                                            'source': 'commit',
                                            'discovered': time(),
                                            'member': member,
                                            'fingerprint': to_match,
                                            'fingerprint_regex': to_match_regex,
                                            'filename': commit_file['filename'],
                                            'patchset': commit_file['patch'],
                                            'link': commit['html_url']
                                        })
                                        redis_client.expire(vuln_id, int(config.vuln_ttl))

                                        pagerduty_alert('{} leaked {} - {}/vulnerability/{}'.format(member, to_match,
                                                                                                    config.hubscrub_url,
                                                                                                    vuln_id),
                                                        dedup_key=vuln_id)

                                        if config.slack_token is not None:
                                            try:
                                                slack_response = slack_alert(
                                                    'commit',
                                                    event_commit['sha'][:6],
                                                    member,
                                                    commit_file['filename'],
                                                    to_match,
                                                    vuln_id
                                                )

                                                redis_client.hmset(vuln_id, {
                                                    'slack_channel': slack_response['channel'],
                                                    'slack_ts': slack_response['ts']
                                                })
                                            except:
                                                app.logger.debug('      ! failed to post to slack')

                    # Mark commit as scanned
                    redis_client.set('commit_{}'.format(event_commit['sha']), '1')

            if event_count >= int(config.events_to_fetch):
                return


def github_gist_scan(member, fingerprints):
    global redis_client
    try:
        redis_client.ping()
    except:
        redis_client = init_redis_client()

    gists = get_member_gists(member)
    gist_count = 0

    # Scan member gists for vulnerabilities
    for gist in gists:
        gist_count += 1

        if not redis_client.exists('gist_{}'.format(gist['id'])):
            app.logger.debug('  - scanning gist {}...'.format(gist['id']))

            if 'files' in gist:
                file_count = 0

                # Scan each file
                for gist_file in gist['files']:
                    file_count += 1

                    if not gist['files'][gist_file]['size'] > 0:
                        break

                    app.logger.debug('    - scanning file {}...'.format(gist['files'][gist_file]['filename']))
                    try:
                        file_contents = authorized_request_raw(gist['files'][gist_file]['raw_url'])
                    except:
                        app.logger.debug('    ! failed to scan file')
                        break

                    for to_match in fingerprints['fingerprints']:
                        to_match_regex = fingerprints['fingerprints'][to_match]
                        match_pattern = re.compile(to_match_regex, re.IGNORECASE)
                        if match_pattern.search(file_contents):
                            app.logger.debug('      ! {} matched \'{}\''.format(
                                gist['files'][gist_file]['filename'], to_match))

                            vuln_id = 'vuln_{}_{}'.format(gist['id'], file_count)

                            if redis_client.exists(vuln_id):
                                break

                            redis_client.hmset(vuln_id, {
                                 'id': vuln_id,
                                 'sha': gist['id'],
                                 'source': 'gist',
                                 'discovered': time(),
                                 'member': member,
                                 'fingerprint': to_match,
                                 'fingerprint_regex': to_match_regex,
                                 'filename': gist['files'][gist_file]['filename'],
                                 'patchset': file_contents,
                                 'link': gist['html_url']
                            })
                            redis_client.expire(vuln_id, int(config.vuln_ttl))

                            pagerduty_alert(
                                '{} leaked {} - {}/vulnerability/{}'.format(member, to_match, config.hubscrub_url,
                                                                            vuln_id), dedup_key=vuln_id)

                            if config.slack_token is not None:
                                try:
                                    slack_response = slack_alert(
                                        'gist',
                                        gist['id'][:6],
                                        member,
                                        gist['files'][gist_file]['filename'],
                                        to_match,
                                        vuln_id
                                    )

                                    redis_client.hmset(vuln_id, {
                                        'slack_channel': slack_response['channel'],
                                        'slack_ts': slack_response['ts']
                                    })
                                except:
                                    app.logger.debug('      ! failed to post to slack')

            # Mark gist as scanned
            redis_client.set('gist_{}'.format(gist['id']), '1')

        if gist_count >= int(config.gists_to_fetch):
            return


def github_scan():
    global redis_client
    try:
        redis_client.ping()
    except:
        redis_client = init_redis_client()

    redis_client.set('scan_in_progress', '1')
    redis_client.expire('scan_in_progress', int(config.scan_ttl))

    # Open JSON fingerprint dictionary
    app.logger.debug('- reading fingerprints.json configuration...')
    with open('fingerprints.json') as fingerprints_file:
        fingerprints = json.load(fingerprints_file)

    organizations = [x.strip() for x in config.organization.split(',')]
    members = {}

    for org in organizations:
        # Get organization members
        app.logger.debug('- fetching {} organization members...'.format(org))
        for member in get_organization_members(org):
            members[member['login']] = 1

    # Iterate over each organization member
    for member in sorted(members, key=lambda x: x.lower()):
        app.logger.debug('- scanning {}...'.format(member))
        github_commit_scan(member, fingerprints)
        github_gist_scan(member, fingerprints)

    # Scan complete
    app.logger.debug('- scan complete!')
    redis_client.delete('scan_in_progress')


def periodic_scan():
    global redis_client
    while True:
        try:
            redis_client.ping()
        except:
            redis_client = init_redis_client()

        if redis_client.exists('scan_in_progress'):
            app.logger.debug('! would launch period scan, but scan already in progress')
        else:
            try:
                github_scan()
            except:
                break

        sleep(int(config.polling_interval))


def start_periodic_scan():
    global redis_client
    try:
        redis_client.ping()
    except:
        redis_client = init_redis_client()

    redis_client.delete('scan_in_progress')

    polling_thread = Thread(target=periodic_scan, args=())
    polling_thread.daemon = True
    polling_thread.start()
