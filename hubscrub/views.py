from collections import deque
from threading import Thread

from time import time
from flask import jsonify, render_template, request, send_file, session

from hubscrub import app, health
from hubscrub.redis import init_redis_client
from hubscrub.scan import github_scan
from hubscrub.slack import slack_approve

import hubscrub.config as config

if config.saml_config is not None:
    import hubscrub.saml


redis_client = init_redis_client()


def authenticated():
    if config.saml_config is not None:
        return 'samlUserdata' in session
    else:
        return None


@app.route('/')
def show_vulnerabilities_list():
    if authenticated() is False:
        return render_template('login.html')

    return render_template('vulnerabilities.html')


@app.route('/log', methods=['GET'])
def show_log():
    if authenticated() is False:
        return render_template('login.html')

    return render_template('log.html')


@app.route('/log/full', methods=['GET'])
def show_log_full():
    if authenticated() is False:
        return render_template('login.html')

    return send_file('/tmp/hubscrub.log',
        mimetype='text/plain',
        attachment_filename='hubscrub.log',
        as_attachment=True
    )


@app.route('/api/log', methods=['GET'])
def api_log():
    if authenticated() is False:
        return jsonify({'ok': False})

    with open('/tmp/hubscrub.log', 'r') as log_file:
        log_deque = deque(log_file, 100)
        log_contents = ''

        while True:
            try:
                log_contents = log_contents + log_deque.popleft()
            except:
                break

        return jsonify({'log': log_contents})


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    global redis_client
    if authenticated() is False:
        return render_template('login.html')

    try:
        redis_client.ping()
    except:
        redis_client = init_redis_client()

    if redis_client.exists('scan_in_progress'):
        return render_template('scan.html', status='in progress')
    else:
        if request.method == 'POST':
            thread = Thread(target=github_scan, args=())
            thread.daemon = True
            thread.start()

            return render_template('scan.html', status='initiated', status_type='success')
        else:
            return render_template('scan.html')


@app.route('/vulnerability/<vulnerability_id>', methods=['GET'])
def show_vulnerability(vulnerability_id):
    if authenticated() is False:
        return render_template('login.html',
            return_to='?return_to=' + request.host_url  + 'vulnerability/{}'.format(vulnerability_id)
        )

    return render_template('vulnerability.html', vulnerability_id=vulnerability_id)


@app.route('/api/vulnerabilities', methods=['GET'])
def api_vulnerabilities():
    global redis_client
    if authenticated() is False:
        return jsonify({'ok': False})

    vulnerabilities = {}

    try:
        redis_client.ping()
    except:
        redis_client = init_redis_client()

    for vuln in redis_client.scan_iter(match='vuln_*'):
        data = redis_client.hgetall(vuln)
        data.pop('patchset', None)
        if 'approved' not in data:
            vulnerabilities[vuln] = data

    sorted_keys = sorted(vulnerabilities, key=lambda x: (
        vulnerabilities[x]['member'].lower(),
        vulnerabilities[x]['source'].lower(),
        vulnerabilities[x]['filename'].lower()
    ))

    sorted_vulnerabilities = []

    for key in sorted_keys:
        sorted_vulnerabilities.append(vulnerabilities[key])

    return jsonify({'vulnerabilities': sorted_vulnerabilities})


@app.route('/api/vulnerability/<vulnerability_id>', methods=['GET', 'POST'])
def api_vulnerability(vulnerability_id):
    global redis_client
    if authenticated() is False:
        return jsonify({'ok': False})

    try:
        redis_client.ping()
    except:
        redis_client = init_redis_client()

    vulnerability = redis_client.hgetall(vulnerability_id)

    if vulnerability:
        if request.method == 'POST':
            if redis_client.hmset(vulnerability_id, {
                'approved': 'true',
                'approved_on': time()
            }):
                approver = None
                if authenticated() is True:
                    approver = session['samlUserdata'].get(config.saml_approver_key)
                    redis_client.hset(vulnerability_id, 'approver', approver)

                app.logger.debug('! vulnerability {} approved'.format(vulnerability_id))

                if config.slack_token is not None:
                    try:
                        approval_thread = Thread(target=slack_approve, args=(
                            vulnerability['slack_channel'],
                            vulnerability['slack_ts'],
                            vulnerability['source'],
                            vulnerability['sha'][:6],
                            vulnerability['member'],
                            vulnerability['filename'],
                            vulnerability['fingerprint'],
                            vulnerability['id'],
                            approver
                        ))
                        approval_thread.daemon = False
                        approval_thread.start()
                    except:
                        app.logger.debug('! failed to post to slack')

                return jsonify({'ok': True})
            else:
                return jsonify({'ok': False})
        else:
            return jsonify(vulnerability)
    else:
        return jsonify({'ok': False})


@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({'now': time(), **health})
