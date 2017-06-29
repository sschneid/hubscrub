import os

github_token = os.environ['GITHUB_API_TOKEN']
organization = os.environ['GITHUB_ORGANIZATION']

saml_config = os.getenv('SAML_CONFIG', None)
saml_approver_key = os.getenv('SAML_APPROVER_KEY', 'User.email')

redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = os.getenv('REDIS_PORT', 6379)

slack_token = os.getenv('SLACK_API_TOKEN', None)
slack_channel = os.getenv('SLACK_CHANNEL', '#hubscrub')

hubscrub_url = os.getenv('HUBSCRUB_URL', 'http://localhost:5000')

rate_limit_ratio = os.getenv('HUBSCRUB_RATE_LIMIT_RATIO', 0.25)
events_to_fetch = os.getenv('HUBSCRUB_EVENTS_TO_FETCH', 5)
gists_to_fetch = os.getenv('HUBSCRUB_GISTS_TO_FETCH', 5)
polling_interval = os.getenv('HUBSCRUB_POLLING_INTERVAL', 3600)

scan_ttl = os.getenv('HUBSCRUB_SCAN_TTL', 1800)
vuln_ttl = os.getenv('HUBSCRUB_VULNERABILITY_TTL', 2592000)

pagerduty_service_key = os.getenv('PAGERDUTY_SERVICE_KEY', None)
