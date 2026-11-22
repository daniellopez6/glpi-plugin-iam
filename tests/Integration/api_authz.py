#!/usr/bin/env python3
# -------------------------------------------------------------------------
# IAM - Identity & Access Governance plugin for GLPI
# Copyright (C) 2026 daniellopez6
# https://github.com/daniellopez6/glpi-plugin-iam
# -------------------------------------------------------------------------
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See LICENSE for the full text.
# -------------------------------------------------------------------------
"""
Authorization verification of the IAM plugin against a live GLPI 12 with the demo data (spec 13 ter, Task 13).

Python 3 standard library only. Credentials never live in the repository:
  IAM_AUTHZ_TOKENS  path of the JSON written by the demo script (`demo_iam.php --profiles`), default
                    ../glpi-plugin-iam-demo/tokens.json relative to the repository. Per user: password, api_token.
                    Optional keys: "base_url", "app_token", "admin" {"api_token"}.
  IAM_APP_TOKEN     API client app token (overrides the file).
  IAM_ADMIN_TOKEN   user token of a Super-Admin (overrides the file): group membership changes, reference reads.
  IAM_GLPI_URL      base URL of GLPI (default http://192.168.88.4).

Every case prints one line (case, user, expected, got, PASS/FAIL). Known plugin bugs, when a case is marked xfail, are
listed separately as XFAIL and do not change the exit code (none at the moment). Exit code: 0 all PASS, 1 any FAIL, 2 configuration error.

Side effects on the demo data (append-only register, cannot be purged by design): each run adds one grant
(source=agent, justification "[iam-authz] ...") and one note on it. Temporary positions are purged at the end;
the owner group membership removed by the Review Focus 4 case is always restored.
"""

import html
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOKENS_PATH = os.environ.get('IAM_AUTHZ_TOKENS') or os.path.join(REPO, '..', 'glpi-plugin-iam-demo', 'tokens.json')
NS = 'GlpiPlugin%5CIam%5C'
ITEMTYPES = ['Resource', 'Role', 'Position', 'Position_Role', 'Position_User', 'Grant', 'Note']

# Demo data (Task 15 report): profiles, entities, resources, roles, grants, users
P_SUPERADMIN, P_ANALYST, P_OWNER, P_AUDITOR, P_AGENT, P_TECH = 4, 15, 16, 17, 18, 6
ENT_FIN, ENT_CLI = 1, 2
RES_CORE, RES_SAPFI, RES_HIS = 6, 7, 13
ROLE_SAPFI_CONSULTA, ROLE_HOMEBANKING_SOPORTE = 11, 14
GRANT_SAPFI = 10          # vrios, SAP-FI Consulta (resource owned by the group of iam.dueno)
GRANT_CORE = 22           # fmolina, Core Banking Administrador (another owner)
GRANT_SHARED = 54         # ssilva (Finandina person) -> HIS (Clinica resource): Review Focus 2
GROUP_FINANZAS = 8        # owner group of SAP-FI
CLINICA_PERSON = 28       # person with a profile in entity 2 (visible to the Clinica analyst)
TICKET = 47               # ticket of entity 1 (viewable by the agent: ticket READALL)
INJECTION = "' OR 1=1 -- "


def die(msg):
    print('CONFIG ERROR: ' + msg, file=sys.stderr)
    sys.exit(2)


try:
    with open(TOKENS_PATH, encoding='utf-8') as fh:
        TOKENS = json.load(fh)
except (OSError, ValueError) as exc:
    die('cannot read the tokens file given by IAM_AUTHZ_TOKENS (%s)' % type(exc).__name__)

BASE = (os.environ.get('IAM_GLPI_URL') or TOKENS.get('base_url') or 'http://192.168.88.4').rstrip('/')
APP_TOKEN = os.environ.get('IAM_APP_TOKEN') or TOKENS.get('app_token') or ''
ADMIN_TOKEN = os.environ.get('IAM_ADMIN_TOKEN') or (TOKENS.get('admin') or {}).get('api_token') or ''
if not APP_TOKEN or not ADMIN_TOKEN:
    die('IAM_APP_TOKEN and IAM_ADMIN_TOKEN (or "app_token"/"admin" in the tokens file) are required')
for login in ('iam.analista', 'iam.dueno', 'iam.auditor', 'iam.agente', 'iam.tecnico', 'iam.clinica'):
    if login not in TOKENS:
        die('user %s missing in the tokens file (run demo_iam.php --profiles)' % login)

RUN_TAG = '[iam-authz] T13 run ' + time.strftime('%Y-%m-%d %H:%M:%S')


# ---------------------------------------------------------------------------------------------------------------
# REST API session
# ---------------------------------------------------------------------------------------------------------------
class Api:
    def __init__(self, label, user_token, profile=None, entity=None, recursive=True):
        self.label = label
        self.session = None
        code, body = self.call('GET', '/initSession', auth=user_token)
        if code != 200 or not isinstance(body, dict):
            die('initSession failed for %s (HTTP %s)' % (label, code))
        self.session = body['session_token']
        if profile is not None:
            code, _ = self.call('POST', '/changeActiveProfile', {'profiles_id': profile})
            if code != 200:
                die('changeActiveProfile %s failed for %s (HTTP %s)' % (profile, label, code))
        if entity is not None:
            self.call('POST', '/changeActiveEntities', {'entities_id': entity, 'is_recursive': recursive})

    def call(self, method, path, body=None, auth=None):
        headers = {'App-Token': APP_TOKEN, 'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'user_token ' + auth
        if self.session:
            headers['Session-Token'] = self.session
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(BASE + '/apirest.php' + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw, code = resp.read(), resp.status
        except urllib.error.HTTPError as err:
            raw, code = err.read(), err.code
        try:
            return code, json.loads(raw) if raw else None
        except ValueError:
            return code, raw.decode('utf-8', 'replace')[:200]

    def get(self, itemtype, item_id):
        return self.call('GET', '/%s%s/%d' % (NS, itemtype, item_id))

    def list(self, itemtype, query=''):
        code, body = self.call('GET', '/%s%s?range=0-4999%s' % (NS, itemtype, query))
        return code, (body if isinstance(body, list) else [])

    def add(self, itemtype, fields):
        code, body = self.call('POST', '/%s%s' % (NS, itemtype), {'input': fields})
        new_id = body.get('id') if isinstance(body, dict) else None
        return code, new_id, body

    def update(self, itemtype, item_id, fields):
        return self.call('PUT', '/%s%s/%d' % (NS, itemtype, item_id), {'input': fields})

    def delete(self, itemtype, item_id, purge=False):
        return self.call('DELETE', '/%s%s/%d%s' % (NS, itemtype, item_id, '?force_purge=1' if purge else ''))

    def close(self):
        if self.session:
            self.call('GET', '/killSession')


# ---------------------------------------------------------------------------------------------------------------
# Web session (cookie jar + GLPI login form; GLPI 12 has no CSRF token in the login form, the kernel checks
# Sec-Fetch-Site/Origin, which urllib does not send)
# ---------------------------------------------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Web:
    def __init__(self, login):
        self.label = login
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)
        self.request('GET', '/')
        code, _, location = self.request('POST', '/front/login.php', {
            'login_name': login, 'login_password': TOKENS[login]['password'], 'noAUTO': '0', 'redirect': '',
        })
        if code not in (302, 303) or 'login.php' in (location or '') or 'error' in (location or '').lower():
            die('web login failed for %s (HTTP %s)' % (login, code))

    def request(self, method, path, form=None, ajax=False):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        headers = {'X-Requested-With': 'XMLHttpRequest'} if ajax else {}
        req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=120) as resp:
                return resp.status, resp.read().decode('utf-8', 'replace'), resp.headers.get('Location')
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode('utf-8', 'replace'), err.headers.get('Location')

    def get(self, path):
        return self.request('GET', path)

    def change_profile(self, profile):
        code, _, _ = self.request('POST', '/Session/ChangeProfile', {'id': str(profile)}, ajax=True)
        return code


# ---------------------------------------------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------------------------------------------
RESULTS = []


def check(case, user, expected, got, ok, xfail=False):
    RESULTS.append({'case': case, 'user': user, 'expected': expected, 'got': str(got), 'ok': bool(ok), 'xfail': xfail})


def denied(code):
    return code in (400, 401, 403, 404)


def ids(rows):
    return sorted(int(r['id']) for r in rows)


def short(values, limit=8):
    values = list(values)
    return ','.join(str(v) for v in values[:limit]) + ('...(%d)' % len(values) if len(values) > limit else '')


def main():
    admin = Api('admin', ADMIN_TOKEN, P_SUPERADMIN)
    tok = {k: v['api_token'] for k, v in TOKENS.items() if isinstance(v, dict) and 'api_token' in v}
    analyst = Api('iam.analista', tok['iam.analista'], P_ANALYST, ENT_FIN)
    owner = Api('iam.dueno', tok['iam.dueno'], P_OWNER, ENT_FIN)
    auditor = Api('iam.auditor', tok['iam.auditor'], P_AUDITOR, ENT_FIN)
    agent = Api('iam.agente', tok['iam.agente'], P_AGENT, ENT_FIN)
    tech = Api('iam.tecnico', tok['iam.tecnico'], P_TECH, ENT_FIN)
    tech_default = Api('iam.tecnico(default)', tok['iam.tecnico'])
    clinic = Api('iam.clinica', tok['iam.clinica'], P_ANALYST, ENT_CLI, False)

    # -- Technician without IAM rights: API ----------------------------------------------------------------------
    for sess, label in ((tech, 'iam.tecnico/Technician'), (tech_default, 'iam.tecnico/default')):
        for it in ITEMTYPES:
            code, body = sess.call('GET', '/%s%s?range=0-50' % (NS, it))
            ok = denied(code) or (code in (200, 206) and body == [])
            check('T1 list %s' % it, label, '401/403 or []', '%s %s' % (code, 'rows=%d' % len(body) if code in (200, 206) and isinstance(body, list) else ''), ok)
        code, _ = sess.get('Grant', GRANT_SAPFI)
        check('T2 GET Grant/%d' % GRANT_SAPFI, label, '401/403/404', code, denied(code))

    # -- Owner A: only grants of A's resources ----------------------------------------------------------------------
    code, groups = admin.call('GET', '/User/%d/Group_User' % user_id(admin, 'iam.dueno'))
    owner_groups = {int(g['groups_id']) for g in groups} if isinstance(groups, list) else set()
    owner_uid = user_id(admin, 'iam.dueno')
    _, all_res = admin.list('Resource')
    owned = {int(r['id']) for r in all_res if int(r.get('users_id_owner') or 0) == owner_uid or int(r.get('groups_id_owner') or 0) in owner_groups}
    _, owner_grants = owner.list('Grant')
    admin_grants = []
    for rid in sorted(owned):
        admin_grants += admin.list('Grant', '&searchText[plugin_iam_resources_id]=^%d$' % rid)[1]
    expected_ids = sorted(int(g['id']) for g in admin_grants if int(g['plugin_iam_resources_id']) in owned)
    foreign = [g['id'] for g in owner_grants if int(g['plugin_iam_resources_id']) not in owned]
    check('O1 list Grant = grants of owned resources %s' % sorted(owned), 'iam.dueno', 'ids == %s' % short(expected_ids),
          'ids=%s foreign=%s' % (short(ids(owner_grants)), foreign), ids(owner_grants) == expected_ids and not foreign and expected_ids)
    code, _ = owner.get('Grant', GRANT_CORE)
    check('O2 GET Grant/%d (other owner)' % GRANT_CORE, 'iam.dueno', '403/404', code, code in (403, 404))
    code, _ = owner.get('Grant', GRANT_SAPFI)
    check('O3 GET Grant/%d (own resource)' % GRANT_SAPFI, 'iam.dueno', '200', code, code == 200)
    _, before = admin.get('Grant', GRANT_SAPFI)
    code, _ = owner.update('Grant', GRANT_SAPFI, {'users_id': CLINICA_PERSON})
    _, after = admin.get('Grant', GRANT_SAPFI)
    check('O4 PUT Grant/%d users_id' % GRANT_SAPFI, 'iam.dueno', 'users_id unchanged',
          'HTTP %s users_id %s->%s' % (code, before.get('users_id'), after.get('users_id')),
          before.get('users_id') == after.get('users_id') and before.get('date_mod') == after.get('date_mod'))
    for it, iid in (('Resource', RES_SAPFI), ('Resource', RES_CORE)):
        code, _ = owner.get(it, iid)
        exp = 200 if iid in owned else 403
        check('O5 GET %s/%d' % (it, iid), 'iam.dueno', exp, code, code == exp or (exp == 403 and code == 404))

    # -- Review Focus 2: shared service grant (Finandina person on a Clinica resource) ------------------------------
    code, _ = clinic.get('Grant', GRANT_SHARED)
    _, rows = clinic.list('Grant')
    check('F2 GET Grant/%d + in list' % GRANT_SHARED, 'iam.clinica (entity 2)', '200, listed', '%s listed=%s' % (code, GRANT_SHARED in ids(rows)),
          code == 200 and GRANT_SHARED in ids(rows))
    for sess, label in ((analyst, 'iam.analista (entity 1)'), (owner, 'iam.dueno (entity 1, not owner of HIS)')):
        code, _ = sess.get('Grant', GRANT_SHARED)
        _, rows = sess.list('Grant')
        check('F2 GET Grant/%d + in list' % GRANT_SHARED, label, '403/404, not listed', '%s listed=%s' % (code, GRANT_SHARED in ids(rows)),
              code in (403, 404) and GRANT_SHARED not in ids(rows))

    # -- Entity-2-only analyst: no Finandina rows, cannot write on Finandina -----------------------------------------
    for it in ITEMTYPES:
        code, rows = clinic.list(it)
        fin = [r['id'] for r in rows if int(r.get('entities_id') or 0) == ENT_FIN]
        check('E1 list %s: no entity-1 rows' % it, 'iam.clinica', 'no entities_id=1', 'HTTP %s rows=%d entity1=%s' % (code, len(rows), short(fin)),
              code in (200, 206) and not fin)
    code, rows = clinic.list('Grant')
    check('E1 list Grant: own entity visible', 'iam.clinica', 'entity-2 grants listed', 'rows=%d' % len(rows), any(int(r['entities_id']) == ENT_CLI for r in rows))
    code, new_id, body = clinic.add('Grant', {'plugin_iam_roles_id': ROLE_HOMEBANKING_SOPORTE, 'users_id': CLINICA_PERSON, 'justification': RUN_TAG + ' must fail'})
    check('E2 POST Grant on Finandina resource', 'iam.clinica', 'refused', 'HTTP %s id=%s' % (code, new_id), denied(code) and not new_id)
    code, _ = clinic.get('Resource', RES_CORE)
    check('E3 GET Resource/%d (Finandina)' % RES_CORE, 'iam.clinica', '403/404', code, code in (403, 404))

    # -- Auditor ---------------------------------------------------------------------------------------------------
    code, new_id, _ = auditor.add('Grant', {'plugin_iam_roles_id': ROLE_HOMEBANKING_SOPORTE, 'users_id': int(before['users_id']), 'tickets_id': TICKET,
                                            'justification': RUN_TAG + ' must fail'})
    check('A1 POST Grant', 'iam.auditor', 'refused', 'HTTP %s id=%s' % (code, new_id), denied(code) and not new_id)
    code, rows = auditor.list('Grant')
    code2, _ = auditor.get('Grant', GRANT_CORE)
    check('A2 GET Grant list + Grant/%d' % GRANT_CORE, 'iam.auditor', '200, rows>0', 'HTTP %s rows=%d GET=%s' % (code, len(rows), code2),
          code in (200, 206) and rows and code2 == 200)

    # -- Agent -----------------------------------------------------------------------------------------------------
    beneficiary = int(before['users_id'])
    code, new_id, _ = agent.add('Grant', {'plugin_iam_roles_id': ROLE_HOMEBANKING_SOPORTE, 'users_id': beneficiary, 'justification': RUN_TAG + ' no ticket'})
    check('G1 POST Grant without ticket', 'iam.agente', 'refused', 'HTTP %s id=%s' % (code, new_id), denied(code) and not new_id)
    code, agent_grant, _ = agent.add('Grant', {'plugin_iam_roles_id': ROLE_HOMEBANKING_SOPORTE, 'users_id': beneficiary, 'tickets_id': TICKET,
                                               'justification': RUN_TAG + ' agent with ticket', 'source': 'manual'})
    row = admin.get('Grant', agent_grant)[1] if agent_grant else {}
    check('G2 POST Grant with ticket', 'iam.agente', '201, source=agent', 'HTTP %s id=%s source=%s' % (code, agent_grant, row.get('source')),
          code == 201 and row.get('source') == 'agent')
    agent_note = None
    if agent_grant:
        code, _ = agent.update('Grant', agent_grant, {'status': 'revoked', 'revoke_reason': RUN_TAG})
        after_g = admin.get('Grant', agent_grant)[1]
        check('G3 PUT Grant status=revoked', 'iam.agente', 'refused, status active', 'HTTP %s status=%s' % (code, after_g.get('status')),
              denied(code) and after_g.get('status') == row.get('status'))
        code, agent_note, _ = agent.add('Note', {'itemtype': 'GlpiPlugin\\Iam\\Grant', 'items_id': agent_grant, 'content': RUN_TAG + ' agent reasoning'})
        check('G4 POST Note on its grant', 'iam.agente', '201', 'HTTP %s id=%s' % (code, agent_note), code == 201 and agent_note)

    # -- Note append-only (spec 13 ter): PUT / DELETE / DELETE force_purge refused, row unchanged --------------------
    note_id = agent_note or 1
    _, note_before = admin.get('Note', note_id)
    for sess, label in ((agent, 'iam.agente'), (analyst, 'iam.analista'), (admin, 'glpi (Super-Admin)')):
        for verb, fn in (('PUT', lambda s: s.update('Note', note_id, {'content': 'tampered', 'users_id': CLINICA_PERSON})),
                         ('DELETE', lambda s: s.delete('Note', note_id)),
                         ('DELETE force_purge', lambda s: s.delete('Note', note_id, True))):
            code, _ = fn(sess)
            code_after, note_after = admin.get('Note', note_id)
            same = code_after == 200 and all(note_after.get(k) == note_before.get(k) for k in ('content', 'users_id', 'items_id', 'date_creation'))
            check('N1 %s Note/%d' % (verb, note_id), label, 'refused, row unchanged', 'HTTP %s unchanged=%s' % (code, same), denied(code) and same)

    # -- Anyone: polymorphic itemtype whitelist and searchText injection ---------------------------------------------
    for sess in (analyst, admin):
        code, new_id, _ = sess.add('Resource', {'name': RUN_TAG + ' user as resource', 'itemtype': 'User', 'items_id': 2, 'entities_id': ENT_FIN})
        check('X1 POST Resource itemtype=User', sess.label, 'refused', 'HTTP %s id=%s' % (code, new_id), denied(code) and not new_id)
        if new_id:
            admin.delete('Resource', new_id, True)
    for sess in (analyst, owner):
        _, base_rows = sess.list('Grant')
        code, rows = sess.list('Grant', '&searchText[justification]=' + urllib.parse.quote(INJECTION))
        check('X2 GET Grant searchText injection', sess.label, '200/206, 0 extra rows', 'HTTP %s rows=%d (baseline %d)' % (code, len(rows), len(base_rows)),
              code in (200, 206) and len(rows) == 0)

    # -- Review Focus 4: owner group membership removed mid-test -----------------------------------------------------
    membership = next((g for g in groups if int(g['groups_id']) == GROUP_FINANZAS), None) if isinstance(groups, list) else None
    if membership is None:
        check('F4 precondition: iam.dueno in group %d' % GROUP_FINANZAS, 'admin', 'member', 'not a member', False)
    else:
        code, _ = owner.get('Resource', RES_SAPFI)
        check('F4 before removal GET Resource/%d' % RES_SAPFI, 'iam.dueno', '200', code, code == 200)
        owner_web = Web('iam.dueno')
        owner_web.change_profile(P_OWNER)
        form = '/plugins/iam/front/resource.form.php?id=%d' % RES_SAPFI
        code, _, _ = owner_web.get(form)
        check('F4 before removal web resource form', 'iam.dueno (web)', '200', code, code == 200)
        restored = False
        try:
            time.sleep(1.2)  # GLPI compares the session group cache date with the last group change, to the second
            code, _ = admin.call('DELETE', '/Group_User/%d?force_purge=1' % int(membership['id']))
            check('F4 admin removes iam.dueno from group %d' % GROUP_FINANZAS, 'admin', '200', code, code == 200)
            code, _ = owner.get('Resource', RES_SAPFI)
            _, rows = owner.list('Grant')
            sapfi = [g['id'] for g in rows if int(g['plugin_iam_resources_id']) == RES_SAPFI]
            check('F4 next request after removal', 'iam.dueno', 'Resource 403/404, no SAP-FI grants', 'GET=%s sapfi_grants=%d' % (code, len(sapfi)),
                  code in (403, 404) and not sapfi)
            code, _ = owner.get('Grant', GRANT_SAPFI)
            check('F4 GET Grant/%d after removal' % GRANT_SAPFI, 'iam.dueno', '403/404', code, code in (403, 404))
            code, _, _ = owner_web.get(form)
            check('F4 next web request after removal', 'iam.dueno (web)', '403', code, code == 403)
            fresh = Api('iam.dueno(new session)', tok['iam.dueno'], P_OWNER, ENT_FIN)
            code, _ = fresh.get('Resource', RES_SAPFI)
            check('F4 new API session after removal', 'iam.dueno (new API session)', '403/404', code, code in (403, 404))
            fresh.close()
        finally:
            time.sleep(1.2)
            code, body = admin.call('POST', '/Group_User', {'input': {
                'users_id': int(membership['users_id']), 'groups_id': GROUP_FINANZAS, 'is_manager': int(membership.get('is_manager') or 0),
                'is_userdelegate': int(membership.get('is_userdelegate') or 0)}})
            restored = code == 201
            check('F4 admin restores the membership (finally)', 'admin', '201', code, restored)
        if restored:
            fresh = Api('iam.dueno(new session)', tok['iam.dueno'], P_OWNER, ENT_FIN)
            code, _ = fresh.get('Resource', RES_SAPFI)
            fresh.close()
            code_web, _, _ = owner_web.get(form)
            check('F4 after restore GET Resource/%d' % RES_SAPFI, 'iam.dueno (new API session + web)', '200, 200', '%s, %s' % (code, code_web),
                  code == 200 and code_web == 200)

    # -- Tree integrity: purge of a position with child positions is refused (even for Super-Admin) -------------------------
    stamp = time.strftime('%H%M%S')
    code, parent, _ = analyst.add('Position', {'name': '[iam-authz] T13 parent ' + stamp, 'entities_id': ENT_FIN, 'comment': RUN_TAG})
    code2, child, _ = analyst.add('Position', {'name': '[iam-authz] T13 child ' + stamp, 'entities_id': ENT_FIN, 'plugin_iam_positions_id': parent or 0,
                                               'comment': RUN_TAG})
    if parent and child:
        code, _ = analyst.delete('Position', parent, True)
        p_code, _ = admin.get('Position', parent)
        check('B0 purge Position (analyst: no CONFIG PURGE)', 'iam.analista', 'refused, parent kept', 'HTTP %s parent_exists=%s' % (code, p_code == 200),
              denied(code) and p_code == 200)
        code, _ = admin.delete('Position', parent, True)
        p_code, _ = admin.get('Position', parent)
        _, child_row = admin.get('Position', child)
        check('B1 purge Position with a child position', 'glpi (Super-Admin)', 'refused, parent kept, child unchanged',
              'HTTP %s parent_exists=%s child.parent=%s' % (code, p_code == 200, child_row.get('plugin_iam_positions_id')),
              denied(code) and p_code == 200 and int(child_row.get('plugin_iam_positions_id') or 0) == parent)
        admin.delete('Position', child, True)
        admin.delete('Position', parent, True)
        leftover = [i for i in (parent, child) if admin.get('Position', i)[0] == 200]
        check('B1 cleanup temporary positions', 'admin', 'purged', 'left=%s' % leftover, not leftover)
    else:
        check('B1 setup positions', 'iam.analista', '201,201', '%s,%s' % (code, code2), False)

    for sess in (analyst, owner, auditor, agent, tech, tech_default, clinic, admin):
        sess.close()

    web_cases()


def user_id(admin, login):
    code, rows = admin.call('GET', '/User?searchText[name]=^%s$&range=0-1' % urllib.parse.quote(login))
    if not isinstance(rows, list) or len(rows) != 1:
        die('user %s not found' % login)
    return int(rows[0]['id'])


# ---------------------------------------------------------------------------------------------------------------
# Web (page level)
# ---------------------------------------------------------------------------------------------------------------
MENU_MARKERS = ('/plugins/iam/', 'Access governance (IAM)', 'Gobierno de accesos (IAM)')


def has_menu(page):
    return any(m in page for m in MENU_MARKERS)


def client_data(page):
    m = re.search(r'data-client="([^"]*)"', page)
    return json.loads(html.unescape(m.group(1))) if m else None


def web_cases():
    # Positive control: the analyst sees the menu and the matrix, and finds the 'missing' cells of SAP-FI
    analyst = Web('iam.analista')
    analyst.change_profile(P_ANALYST)
    code, page, _ = analyst.get('/front/central.php')
    check('W0 central page has IAM menu (control)', 'iam.analista', 'menu present', 'HTTP %s menu=%s' % (code, has_menu(page)), code == 200 and has_menu(page))
    code, page, _ = analyst.get('/plugins/iam/front/matrix.php?resource=%d' % RES_SAPFI)
    data = client_data(page) or {}
    missing_cells = [k for k, v in (data.get('cells') or {}).items() if v[2] is not None and v[2] > v[1]]
    check('W0 matrix SAP-FI has expected counts (control)', 'iam.analista', 'members=true, missing cells>0',
          'HTTP %s members=%s missing_cells=%s' % (code, data.get('members'), short(missing_cells)), code == 200 and data.get('members') is True and missing_cells)
    miss_panels = []
    for key in missing_cells:
        pos, role = key.split(':')
        c, frag, _ = analyst.get('/plugins/iam/ajax/matrixcell.php?position=%s&role=%s' % (pos, role))
        if c == 200 and 'iam-chip-miss' in frag:
            miss_panels.append(key)
    check('W0 matrixcell lists missing holders (control)', 'iam.analista', 'iam-chip-miss present', 'cells=%s' % short(miss_panels), miss_panels)

    # Technician: no menu, 403 on every page (login with the default profile, then the Technician profile)
    tech = Web('iam.tecnico')
    code, page, _ = tech.get('/Helpdesk')  # default profile: Self-Service (helpdesk interface)
    check('W1 no IAM menu (default profile)', 'iam.tecnico', 'menu absent', 'HTTP %s menu=%s' % (code, has_menu(page)), code == 200 and not has_menu(page))
    pc = tech.change_profile(P_TECH)
    code, page, _ = tech.get('/front/central.php')
    check('W1 no IAM menu (Technician profile)', 'iam.tecnico', 'menu absent', 'profile=%s HTTP %s menu=%s' % (pc, code, has_menu(page)),
          pc == 200 and code == 200 and not has_menu(page))
    pos, role = (missing_cells[0].split(':') if missing_cells else ('0', str(ROLE_SAPFI_CONSULTA)))
    for path in ('/plugins/iam/front/matrix.php', '/plugins/iam/front/search.php?q=SAP', '/plugins/iam/ajax/matrixcell.php?position=%s&role=%s' % (pos, role),
                 '/plugins/iam/front/grant.php', '/plugins/iam/front/resource.php', '/plugins/iam/front/position.php',
                 '/plugins/iam/front/grant.form.php?id=%d' % GRANT_SAPFI):
        code, _, _ = tech.get(path)
        check('W2 %s' % path.split('?')[0].replace('/plugins/iam/', ''), 'iam.tecnico/Technician', '403', code, code == 403)

    # Owner: matrix without expected/missing data, panels without 'missing' holders
    owner = Web('iam.dueno')
    owner.change_profile(P_OWNER)
    code, page, _ = owner.get('/plugins/iam/front/matrix.php')
    data = client_data(page) or {}
    expected_values = [k for k, v in (data.get('cells') or {}).items() if v[2] is not None]
    check('W3 owner matrix: no expected/missing data', 'iam.dueno', 'members=false, no expected, no iam-miss',
          'HTTP %s members=%s expected_cells=%d iam-miss=%s' % (code, data.get('members'), len(expected_values), 'class="iam-miss"' in page),
          code == 200 and data.get('members') is False and not expected_values and 'class="iam-miss"' not in page and 'iam-count">3/4' not in page)
    leaks = []
    for key in missing_cells:
        p, r = key.split(':')
        c, frag, _ = owner.get('/plugins/iam/ajax/matrixcell.php?position=%s&role=%s' % (p, r))
        if c == 200 and 'iam-chip-miss' in frag:
            leaks.append(key)
    check('W4 owner matrixcell on cells with missing people', 'iam.dueno', 'no iam-chip-miss', 'cells=%d leaks=%s' % (len(missing_cells), leaks),
          missing_cells and not leaks)


def report():
    width = (44, 34, 34, 44)
    line = '%-{0}s %-{1}s %-{2}s %-{3}s %s'.format(*width)
    print(line % ('case', 'user', 'expected', 'got', 'result'))
    print('-' * 168)
    for r in [r for r in RESULTS if not r['xfail']]:
        print(line % (r['case'][:width[0]], r['user'][:width[1]], str(r['expected'])[:width[2]], r['got'][:width[3]], 'PASS' if r['ok'] else 'FAIL'))
    xf = [r for r in RESULTS if r['xfail']]
    if xf:
        print('\nKnown plugin bugs (XFAIL: expected to fail until fixed; XPASS means the bug is fixed)')
        for r in xf:
            print(line % (r['case'][:width[0]], r['user'][:width[1]], str(r['expected'])[:width[2]], r['got'][:width[3]], 'XPASS' if r['ok'] else 'XFAIL'))
    passed = sum(1 for r in RESULTS if r['ok'] and not r['xfail'])
    failed = sum(1 for r in RESULTS if not r['ok'] and not r['xfail'])
    print('\nPASS %d  FAIL %d  XFAIL %d  XPASS %d' % (passed, failed, sum(1 for r in xf if not r['ok']), sum(1 for r in xf if r['ok'])))
    return failed


if __name__ == '__main__':
    try:
        main()
    finally:
        failures = report()
    sys.exit(1 if failures else 0)
