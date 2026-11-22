/**
 * -------------------------------------------------------------------------
 * IAM - Identity & Access Governance plugin for GLPI
 * Copyright (C) 2026 daniellopez6
 * https://github.com/daniellopez6/glpi-plugin-iam
 * -------------------------------------------------------------------------
 * LICENSE
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version. See LICENSE for the full text.
 * -------------------------------------------------------------------------
 */

/*
 * RBAC matrix (front/matrix.php): expands resource columns into roles, opens the nominal panel of a cell, quick text
 * filter, area groups and edit mode. Data comes from the data-client attribute (JSON); every text is inserted with
 * textContent, never as HTML. The only HTML inserted is the panel fragment rendered (and escaped) by the server.
 */
(function () {
    'use strict';

    const GLYPHS = {a: 'ti-check', r: 'ti-circle-half-2', f: 'ti-ban'};
    const CLASSES = {a: 'iam-e-allowed', r: 'iam-e-on_request', f: 'iam-e-forbidden'};
    const API_VALUES = {a: 'allowed', r: 'on_request', f: 'forbidden', '': ''};
    const CODES = {allowed: 'a', on_request: 'r', forbidden: 'f'};

    function el(tag, className, text) {
        const node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (text !== undefined && text !== null) {
            node.textContent = String(text);
        }
        return node;
    }

    function icon(name, extra) {
        const i = el('i', 'ti ' + name + (extra ? ' ' + extra : ''));
        i.setAttribute('aria-hidden', 'true');
        return i;
    }

    function toast(message, isError) {
        const fn = isError ? window.glpi_toast_error : window.glpi_toast_info;
        if (typeof fn === 'function') {
            fn(message);
        } else if (isError) {
            window.alert(message);
        }
    }

    function init(root) {
        let data;
        try {
            data = JSON.parse(root.dataset.client || '{}');
        } catch (e) {
            return;
        }
        const t = data.i18n || {};
        const cells = data.cells || {};
        const members = !!data.members;
        const table = document.getElementById('iam-matrix-table');

        // Auto-submit of the server-side filters
        root.querySelectorAll('[data-iam-autosubmit]').forEach(function (input) {
            input.addEventListener('change', function () {
                input.form.submit();
            });
        });

        if (!table) {
            return;
        }

        const headRow = table.tHead.rows[0];
        const resHeaders = Array.from(headRow.querySelectorAll('th.iam-res'));
        const colIndex = new Map();
        resHeaders.forEach(function (th, i) {
            colIndex.set(String(th.dataset.res), i);
        });
        const rolesOf = new Map();
        (data.cols || []).forEach(function (c) {
            rolesOf.set(String(c[0]), c[1]);
        });
        const roleInfo = new Map();
        (data.cols || []).forEach(function (c) {
            c[1].forEach(function (r) {
                roleInfo.set(String(r[0]), r);
            });
        });

        // Data rows and their aggregate cells (one per resource, in header order)
        const rows = Array.from(table.querySelectorAll('tr[data-pos]'));
        rows.forEach(function (tr) {
            tr.iamAgg = Array.from(tr.children).filter(function (c) {
                return c.tagName === 'TD';
            });
        });
        // Inserted role cells per resource, to collapse them again
        const expanded = new Map();

        // ---- Role-level cells ---------------------------------------------------------------------------------
        function renderRoleCell(td) {
            const key = td.dataset.key;
            const c = cells[key];
            td.textContent = '';
            td.removeAttribute('title');
            td.classList.remove('iam-has-dev', 'iam-has-forbidden');
            if (!c) {
                return;
            }
            const code = c[0];
            if (code !== '') {
                td.appendChild(icon(GLYPHS[code], CLASSES[code]));
            } else {
                td.appendChild(el('span', 'iam-e-none', '·'));
            }
            if (c[2] > 0) {
                td.appendChild(el('span', 'iam-count', c[1] + '/' + c[2]));
            } else if (c[1] > 0) {
                td.appendChild(el('span', 'iam-count', c[1]));
            }
            const dev = c[3] + c[4];
            if (dev > 0) {
                td.classList.add('iam-has-dev');
                if (c[4] > 0) {
                    td.classList.add('iam-has-forbidden');
                }
                const badge = el('span', 'iam-dev');
                badge.appendChild(icon(c[4] > 0 ? 'ti-ban' : 'ti-alert-triangle'));
                badge.appendChild(document.createTextNode(String(dev)));
                td.appendChild(badge);
            }
            const missing = code === 'a' ? c[2] - c[1] : 0;
            if (missing > 0 && members) {
                const miss = el('span', 'iam-miss');
                miss.appendChild(icon('ti-point-filled'));
                miss.appendChild(document.createTextNode(String(missing)));
                td.appendChild(miss);
            }
        }

        function roleCellTitle(key) {
            const c = cells[key];
            if (!c) {
                return t[''] || '';
            }
            const parts = [t[c[0]] || ''];
            if (c[2] > 0) {
                parts.push((t.holding || '') + ': ' + c[1] + ' / ' + (t.expected || '') + ': ' + c[2]);
            } else if (c[1] > 0) {
                parts.push((t.holding || '') + ': ' + c[1]);
            }
            if (c[3] > 0) {
                parts.push((t.unexpected || '') + ': ' + c[3]);
            }
            if (c[4] > 0) {
                parts.push((t.forbidden || '') + ': ' + c[4]);
            }
            if (c[0] === 'a' && c[2] - c[1] > 0 && members) {
                parts.push((t.missing || '') + ': ' + (c[2] - c[1]));
            }
            return parts.join(' · ');
        }

        function expand(resId) {
            resId = String(resId);
            if (expanded.has(resId) || !colIndex.has(resId)) {
                return;
            }
            const roles = rolesOf.get(resId) || [];
            const idx = colIndex.get(resId);
            const th = resHeaders[idx];
            const inserted = [];
            let after = th;
            roles.forEach(function (r) {
                const rth = el('th', 'iam-role');
                rth.scope = 'col';
                rth.dataset.role = String(r[0]);
                rth.dataset.res = resId;
                const label = el('span', 'iam-role-name', r[1]);
                rth.title = r[1] + (r[2] === 'privileged' ? ' — ' + (t.privileged || '') : '') + (r[3] ? ' — ' + (t.breakglass || '') : '');
                if (r[2] === 'privileged') {
                    const shield = icon('ti-shield-half-filled', 'iam-priv');
                    shield.removeAttribute('aria-hidden');
                    shield.setAttribute('aria-label', t.privileged || '');
                    rth.appendChild(shield);
                }
                if (r[3]) {
                    rth.appendChild(icon('ti-urgent', 'iam-bg'));
                }
                rth.appendChild(label);
                after.after(rth);
                after = rth;
                inserted.push(rth);
            });
            rows.forEach(function (tr) {
                let prev = tr.iamAgg[idx];
                const pos = tr.dataset.pos;
                roles.forEach(function (r) {
                    const td = el('td', 'iam-rc');
                    td.dataset.key = pos + ':' + r[0];
                    renderRoleCell(td);
                    prev.after(td);
                    prev = td;
                    inserted.push(td);
                });
            });
            th.classList.add('iam-open');
            th.querySelector('.iam-res-btn').setAttribute('aria-expanded', 'true');
            rows.forEach(function (tr) {
                tr.iamAgg[idx].classList.add('iam-open');
            });
            expanded.set(resId, inserted);
            applyFilter();
        }

        function collapse(resId) {
            resId = String(resId);
            const inserted = expanded.get(resId);
            if (!inserted) {
                return;
            }
            inserted.forEach(function (node) {
                node.remove();
            });
            expanded.delete(resId);
            const idx = colIndex.get(resId);
            resHeaders[idx].classList.remove('iam-open');
            resHeaders[idx].querySelector('.iam-res-btn').setAttribute('aria-expanded', 'false');
            rows.forEach(function (tr) {
                tr.iamAgg[idx].classList.remove('iam-open');
            });
        }

        function toggle(resId) {
            if (expanded.has(String(resId))) {
                collapse(resId);
            } else {
                expand(resId);
            }
        }

        // ---- Nominal panel ------------------------------------------------------------------------------------
        const panelEl = document.getElementById('iam-panel');
        const panelBody = document.getElementById('iam-panel-body');
        let panelRequest = 0;

        function openPanel(pos, role) {
            if (!panelEl || !window.bootstrap) {
                return;
            }
            const ticket = ++panelRequest;
            panelBody.textContent = '';
            panelBody.appendChild(el('div', 'text-secondary', t.loading || '…'));
            window.bootstrap.Offcanvas.getOrCreateInstance(panelEl).show();
            const url = new URL(root.dataset.cellUrl, window.location.href);
            url.searchParams.set('position', pos);
            url.searchParams.set('role', role);
            fetch(url.toString(), {credentials: 'same-origin', headers: {'X-Requested-With': 'XMLHttpRequest'}})
                .then(function (response) {
                    if (!response.ok) {
                        throw new Error(String(response.status));
                    }
                    return response.text();
                })
                .then(function (html) {
                    if (ticket === panelRequest) {
                        // Server-rendered fragment, escaped by Twig
                        panelBody.innerHTML = html;
                    }
                })
                .catch(function () {
                    if (ticket === panelRequest) {
                        panelBody.textContent = '';
                        panelBody.appendChild(el('div', 'alert alert-danger', t.panelError || ''));
                    }
                });
        }

        // ---- Edit mode ----------------------------------------------------------------------------------------
        const editToggle = document.getElementById('iam-edit-toggle');
        let editing = false;
        let menu = null;

        function closeMenu() {
            if (menu) {
                menu.remove();
                menu = null;
            }
        }

        function save(td, code) {
            const key = td.dataset.key;
            const [pos, role] = key.split(':');
            const before = cells[key] ? cells[key].slice() : undefined;
            // Optimistic update, reverted on any error
            cells[key] = before ? [code].concat(before.slice(1)) : [code, 0, 0, 0, 0];
            renderRoleCell(td);
            td.classList.add('iam-saving');
            const body = new FormData();
            body.append('position', pos);
            body.append('role', role);
            body.append('expectation', API_VALUES[code]);
            fetch(root.dataset.editUrl, {
                method: 'POST',
                body: body,
                credentials: 'same-origin',
                headers: {'X-Requested-With': 'XMLHttpRequest'}
            })
                .then(function (response) {
                    return response.json().catch(function () {
                        return {ok: false, message: t.failed || ''};
                    });
                })
                .then(function (reply) {
                    if (!reply || reply.ok !== true) {
                        throw new Error((reply && reply.message) || t.failed || '');
                    }
                    if (Array.isArray(reply.counts)) {
                        cells[key] = reply.counts;
                    } else {
                        cells[key] = [CODES[reply.expectation] || '', 0, 0, 0, 0];
                    }
                    renderRoleCell(td);
                    toast(t.saved || '', false);
                })
                .catch(function (error) {
                    if (before) {
                        cells[key] = before;
                    } else {
                        delete cells[key];
                    }
                    renderRoleCell(td);
                    toast(error.message || t.failed || '', true);
                })
                .finally(function () {
                    td.classList.remove('iam-saving');
                });
        }

        function openMenu(td) {
            closeMenu();
            const current = cells[td.dataset.key] ? cells[td.dataset.key][0] : '';
            menu = el('div', 'dropdown-menu show iam-edit-menu');
            menu.setAttribute('role', 'menu');
            menu.appendChild(el('h6', 'dropdown-header', t.set || ''));
            ['a', 'r', 'f', ''].forEach(function (code) {
                const item = el('button', 'dropdown-item' + (code === current ? ' active' : ''));
                item.type = 'button';
                item.setAttribute('role', 'menuitemradio');
                item.setAttribute('aria-checked', code === current ? 'true' : 'false');
                if (code !== '') {
                    item.appendChild(icon(GLYPHS[code], CLASSES[code] + ' me-2'));
                } else {
                    item.appendChild(el('span', 'iam-e-none me-2', '·'));
                }
                item.appendChild(document.createTextNode(t[code] || ''));
                item.addEventListener('click', function (ev) {
                    ev.stopPropagation();
                    closeMenu();
                    if (code !== current) {
                        save(td, code);
                    }
                });
                menu.appendChild(item);
            });
            document.body.appendChild(menu);
            const rect = td.getBoundingClientRect();
            menu.style.position = 'absolute';
            menu.style.top = (window.scrollY + rect.bottom + 2) + 'px';
            menu.style.left = Math.max(4, window.scrollX + rect.left - 40) + 'px';
            const first = menu.querySelector('button');
            if (first) {
                first.focus();
            }
        }

        if (editToggle) {
            editToggle.addEventListener('click', function () {
                editing = !editing;
                editToggle.setAttribute('aria-pressed', editing ? 'true' : 'false');
                editToggle.classList.toggle('active', editing);
                table.classList.toggle('iam-editing', editing);
                closeMenu();
            });
        }
        document.addEventListener('click', function (ev) {
            if (menu && !menu.contains(ev.target)) {
                closeMenu();
            }
        });
        document.addEventListener('keydown', function (ev) {
            if (ev.key === 'Escape') {
                closeMenu();
            }
        });

        // ---- Clicks on the table ------------------------------------------------------------------------------
        table.addEventListener('click', function (ev) {
            const resBtn = ev.target.closest('.iam-res-btn');
            if (resBtn) {
                toggle(resBtn.closest('th').dataset.res);
                return;
            }
            const areaBtn = ev.target.closest('.iam-area-btn');
            if (areaBtn) {
                const group = areaBtn.closest('tbody');
                const collapsed = group.classList.toggle('iam-collapsed');
                areaBtn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
                return;
            }
            const td = ev.target.closest('td');
            if (!td || !table.contains(td)) {
                return;
            }
            const tr = td.parentElement;
            if (td.dataset.key) {
                ev.stopPropagation();
                const pos = tr.dataset.pos;
                if (editing && pos !== '0') {
                    openMenu(td);
                } else if (cells[td.dataset.key]) {
                    openPanel(pos, td.dataset.key.split(':')[1]);
                }
                return;
            }
            const idx = tr.iamAgg ? tr.iamAgg.indexOf(td) : -1;
            if (idx >= 0) {
                toggle(resHeaders[idx].dataset.res);
            }
        });

        // Lazy tooltips of role cells
        table.addEventListener('mouseover', function (ev) {
            const td = ev.target.closest('td[data-key]');
            if (td && !td.title) {
                td.title = roleCellTitle(td.dataset.key);
            }
        });

        root.querySelectorAll('[data-iam-expand]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                const all = btn.dataset.iamExpand === 'all';
                resHeaders.forEach(function (th) {
                    if (th.classList.contains('iam-filtered')) {
                        return;
                    }
                    if (all) {
                        expand(th.dataset.res);
                    } else {
                        collapse(th.dataset.res);
                    }
                });
            });
        });

        // ---- Quick text filter (client side) ------------------------------------------------------------------
        const quick = document.getElementById('iam-quickfilter');
        let filterActive = false;

        function applyFilter() {
            const q = quick ? quick.value.trim().toLowerCase() : '';
            if (q === '' && !filterActive) {
                return;
            }
            filterActive = q !== '';
            const rowHit = rows.filter(function (tr) {
                return q !== '' && (tr.dataset.name || '').includes(q);
            });
            const colHit = resHeaders.filter(function (th) {
                return q !== '' && (th.dataset.name || '').includes(q);
            });
            const filterRows = rowHit.length > 0 || colHit.length === 0;
            rows.forEach(function (tr) {
                tr.hidden = q !== '' && filterRows && !rowHit.includes(tr);
            });
            resHeaders.forEach(function (th, idx) {
                const hide = q !== '' && colHit.length > 0 && !colHit.includes(th);
                th.classList.toggle('iam-filtered', hide);
                rows.forEach(function (tr) {
                    tr.iamAgg[idx].classList.toggle('iam-filtered', hide);
                });
                (expanded.get(String(th.dataset.res)) || []).forEach(function (node) {
                    node.classList.toggle('iam-filtered', hide);
                });
            });
            // Hide the area groups left without visible rows
            table.querySelectorAll('tbody.iam-group').forEach(function (group) {
                const any = Array.from(group.querySelectorAll('tr[data-pos]')).some(function (tr) {
                    return !tr.hidden;
                });
                group.hidden = !any;
            });
        }

        if (quick) {
            let timer = null;
            quick.addEventListener('input', function () {
                window.clearTimeout(timer);
                timer = window.setTimeout(applyFilter, 150);
            });
        }
    }

    function start() {
        const root = document.getElementById('iam-matrix');
        if (root) {
            init(root);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
