from slackclient import SlackClient
from time import asctime

import hubscrub.config as config


def init_slack_client():
    slack_client = SlackClient(config.slack_token)

    return slack_client


def slack_post(channel, source, sha, member, filename, fingerprint, link, approve=None, approver=None):
    slack_client = init_slack_client()

    text = "{} `{}` matched *{}*".format(source, sha, fingerprint)

    if approve is not None:
        footer = ':white_check_mark: - approved'
        if approver is not None:
            footer += ' by {} on {}'.format(approver, asctime())
        else:
            footer += ' on {}'.format(asctime())

        return slack_client.api_call(
            'chat.update',
            ts=approve,
            channel=channel,
            attachments=[{
                'author_name': member,
                'title': '{}'.format(filename),
                'title_link': '{}/vulnerability/{}'.format(config.hubscrub_url, link),
                'color': 'good',
                'text': text,
                'mrkdwn_in': ['text'],
                'footer': footer
            }]
        )
    else:
        return slack_client.api_call(
            'chat.postMessage',
            channel=config.slack_channel,
            attachments=[{
                'author_name': member,
                'title': '{}'.format(filename),
                'title_link': '{}/vulnerability/{}'.format(config.hubscrub_url, link),
                'color': 'danger',
                'text': text,
                'mrkdwn_in': ['text'],
            }],
            username='hubscrub',
            icon_emoji=':warning:'
        )



def slack_alert(source, sha, member, filename, fingerprint, link):
    return slack_post(config.slack_channel, source, sha, member, filename, fingerprint, link)


def slack_approve(channel, ts, source, sha, member, filename, fingerprint, link, approver=None):
    return slack_post(channel, source, sha, member, filename, fingerprint, link, ts, approver)
