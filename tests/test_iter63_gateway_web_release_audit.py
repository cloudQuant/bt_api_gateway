"""Web and CLI on one journal with the release audit: each release names its operator (I63-E144).

Synthetic Gateway with a real Registry, CURVE over loopback and a real journal; no venue.
"""
from test_iter63_gateway_web_gateway_authority import Gateway, WebHost, cli_call, operator_origin

WEB = operator_origin('web-account-op', 'web-account-app')
CLI = operator_origin('cli-op', 'cli-app')
CONFLICT = {'status': 'REQUEST_REJECTED', 'code': 'REQUEST_ID_CONFLICT'}


def _prepare(gateway):
    cli = gateway.runtime('cli')
    journal_id = cli_call(cli, 'cli', 'direct.control.identity', {}, gateway)['journal_id']
    for cause_id in ('cause-1', 'cause-2', 'cause-3'):
        cli_call(cli, 'cli', 'direct.control.apply',
                 {'cause_id': cause_id, 'mode': 'FREEZE', 'expected_journal_id': journal_id}, gateway)

    def release(cause_id, operation_id):
        return cli_call(cli, 'cli', 'direct.control.resume', {'cause_id': cause_id, 'expected_version': 1,
                        'operation_id': operation_id, 'expected_journal_id': journal_id}, gateway)

    def release_status(operation_id):
        return cli_call(cli, 'cli', 'direct.control.resume_status', {'operation_id': operation_id}, gateway)

    return release, release_status


def _stored_releasers(gateway):
    def read():
        with gateway.journal._transaction() as db:
            return {row['cause_id']: row['releaser'] for row in db.execute('SELECT * FROM direct_control_releases')}
    return gateway.on_owner(read)


def test_each_release_names_its_operator_on_the_web_and_on_the_cli(tmp_path):
    with Gateway(tmp_path, release_audit=True) as gateway:
        release, release_status = _prepare(gateway)
        web = WebHost(gateway, ('account',))

        async def check(browser):
            # A release through the Web is recorded for the Web operator, and every view says so.
            command = await browser.resume_command('account', 'web-release-1', 'cause-1')
            receipt = (await browser.prepare('account', command))['receipt']
            done = await browser.run('account', receipt)
            assert done == {'status': 'OBSERVED', 'cause_id': 'cause-1', 'version': 2, 'active': False,
                            'releaser': WEB}
            assert (await browser.status('account', receipt))['releaser'] == WEB
            assert release_status('web-release-1')['releaser'] == WEB
            # A release through the CLI is recorded for the CLI operator.
            assert release('cause-2', 'cli-release-2')['releaser'] == CLI
            _, view = await browser.causes('account')
            rows = {row['cause_id']: row for row in view['causes']}
            assert (rows['cause-1']['releaser'], rows['cause-2']['releaser']) == (WEB, CLI)
            assert 'releaser' not in rows['cause-3'] and rows['cause-3']['active'] == 1
            # A repeat of the Web's release by the CLI operator returns the stored record: the
            # first releaser is kept.
            assert release('cause-1', 'web-release-1')['releaser'] == WEB
            # The Web operator saw cause-3 active and prepared its release; the CLI operator
            # then released it under the same id. That release is the CLI operator's, not this
            # request: it is not reported as done by the Web operator and is not sent again.
            command = await browser.resume_command('account', 'shared-release', 'cause-3')
            receipt = (await browser.prepare('account', command))['receipt']
            assert release('cause-3', 'shared-release')['releaser'] == CLI
            assert await browser.status('account', receipt) == CONFLICT
            assert await browser.run('account', receipt) == CONFLICT

        web.run(check)
        assert _stored_releasers(gateway) == {'cause-1': WEB, 'cause-2': CLI, 'cause-3': CLI}


def test_without_the_audit_no_release_names_anyone(tmp_path):
    # As before the audit existed: no releaser anywhere, and the journal cannot tell whose
    # release an operation id was, so the same id on the same cause reads as this request.
    with Gateway(tmp_path) as gateway:
        release, release_status = _prepare(gateway)
        web = WebHost(gateway, ('account',))

        async def check(browser):
            command = await browser.resume_command('account', 'web-release-1', 'cause-1')
            receipt = (await browser.prepare('account', command))['receipt']
            assert await browser.run('account', receipt) == {
                'status': 'OBSERVED', 'cause_id': 'cause-1', 'version': 2, 'active': False}
            assert 'releaser' not in release_status('web-release-1')
            assert 'releaser' not in release('cause-2', 'cli-release-2')
            _, view = await browser.causes('account')
            assert all('releaser' not in row for row in view['causes'])
            command = await browser.resume_command('account', 'shared-release', 'cause-3')
            receipt = (await browser.prepare('account', command))['receipt']
            release('cause-3', 'shared-release')
            status = await browser.status('account', receipt)
            assert status['status'] == 'OBSERVED' and status['active'] is False

        web.run(check)

        def tables():
            with gateway.journal._transaction() as db:
                return {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        assert 'direct_control_releases' not in gateway.on_owner(tables)
