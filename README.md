# hubscrub [![Build Status](https://travis-ci.org/sschneid/hubscrub.svg?branch=master)](https://travis-ci.org/sschneid/hubscrub)

hubscrub is a whitehat security tool allowing organizations to monitor the public commits and gists of their members and alert when defined patterns are detected.

# features

- simple "approve and remove from dashboard" auditing workflow
- percentage-based github rate-limit adherence
- unlimited organization size, can specify multiple organizations
- optional notifcations via [slack](https://slack.com) and [pagerduty](https://pagerduty.com/)
- optional saml handshake authentication

# requirements

`libxml2`, `libxmlsec1-dev`, and `pkg-config` are all library prerequisites for hubscrub.

## osx (mac)

install via brew:

```
brew install libxml2 libxmlsec1 pkg-config
```

# docker quickstart

```
docker build -t hubscrub . \
  && docker run -e 'GITHUB_ORGANIZATION=your-organization' -e 'GITHUB_API_TOKEN=abcdefg' -p 80:5000 -it hubscrub
```

# configuration env settings

passed to docker via `-e` or `--env-file`:

| env | setting |
| --- | --- |
| `GITHUB_API_TOKEN` | a github api token |
| `GITHUB_ORGANIZATION` | the github organization(s) to scan, csv |

# more (optional) configuration env settings

also passed to docker via `-e` or `--env-file`:

| env | setting | default |
| --- | --- | --- |
| `HUBSCRUB_URL` | the url to your hubscrub instance | `http://localhost:5000` |
| `HUBSCRUB_RATE_LIMIT_RATIO` | how much remaining rate quota to pause at (eg. `0.25` == "75% used") | `0.25` |
| `HUBSCRUB_EVENTS_TO_FETCH` | how many new user events to fetch | `5` |
| `HUBSCRUB_GISTS_TO_FETCH` | how many new user gists to fetch | `5` |
| `HUBSCRUB_POLLING_INTERVAL` | how often to run periodic scans | `3600` |
| `HUBSCRUB_SCAN_TTL` | time-to-live of a scan process | `1800` |
| `HUBSCRUB_VULNERABILITY_TTL` | time-to-live of a vulnerability record | `2592000` |
| `REDIS_HOST` | hostname of an external redis instance | `localhost` |
| `REDIS_PORT` | port redis is listening on | `6379` |
| `SLACK_API_TOKEN` | a slack api token | `None` |
| `SLACK_CHANNEL` | which slack channel to post alerts to | `#hubscrub` |
| `PAGERDUTY_SERVICE_KEY` | a pagerduty api service key | `None` |
| `PAGERDUTY_ALERT_INTERVAL` | how long before paging on unacknowledged vulnerabilities | `3600` |
| `SAML_CONFIG` | a [saml configuration](https://github.com/onelogin/python3-saml#settings) json blob | `None` |

# fingerprints.json

keys and regular expression patterns to match against.  the included example searches for aws credential keys and private ssh keys:

```json
{
    "fingerprints": {
        "aws_access_key_id": "\\baws[_-]access[_-]key[_-]id\\b.*\\b\\w{20}\\b",
        "aws_secret_access_key": "\\baws[_-]secret[_-]access[_-]key\\b.*\\b.*\\b[0-9a-zA-Z_\\+\\/]{40}\\b",
        "rsa private key": "begin rsa private key"
    }
}
```

note that all backslashes (`\`) must be double-escaped in json as `\\`.

# secure af

artwork by jason travis ([jasontravisdesign.com](https://jasontravisdesign.com/))
