<?php

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

namespace GlpiPlugin\Iam;

use Glpi\DBAL\QueryIdentifier;
use Glpi\DBAL\QuerySubQuery;
use Session;
use Ticket;
use User;

/**
 * Data access of the RBAC matrix page, its nominal panel and its edit mode.
 *
 * Every read applies the visibility predicate of its table (the same ones as the search engine and the API):
 * Resource / Role / Position_Role / Grant / Position_User ::visibilityCriteria(), and GLPI's recursion-aware entity
 * restriction for positions. The page reads ONE query per table (Review Focus 5); the panel is loaded per cell.
 *
 * People of a position are only listed with the read right on the register (Position_User::canView()). A session
 * that sees the register only through ownership (asset owner, READ_OWNED) sees only the assignments that justify or
 * forbid a grant it can see (see assignmentCriteria()): enough to tell whether each access to its resources is
 * expected, not who lacks one. For such sessions the server never sends the 'missing' people nor the figures derived
 * from them (expected, complete, missing), and only the positions with something to show are rows.
 */
final class Matrix
{
    /** Sessions that can open the matrix: the catalogue readers (CONFIG READ) and the asset owners (ACCESS READ_OWNED). */
    public static function canView(): bool
    {
        return Resource::canView();
    }

    /** Edit mode: CONFIG UPDATE (each write is checked again on the cell by Position_Role::upsert()). */
    public static function canEdit(): bool
    {
        return Position_Role::canUpdate();
    }

    /** The members of every visible position are visible (otherwise only holders of visible grants). */
    public static function membersVisible(): bool
    {
        return Position_User::canView();
    }

    private static function today(): string
    {
        return date('Y-m-d');
    }

    /** @return array<mixed> */
    private static function positionCriteria(): array
    {
        return getEntitiesRestrictCriteria(Position::getTable(), '', '', true);
    }

    /**
     * Assignments the session may use.
     *
     * - Register readers (Position_User::canView()): Position_User::visibilityCriteria().
     * - Asset owners (READ_OWNED only), the minimum needed to qualify the grants they can see. An assignment row
     *   (users_id U, positions_id P) is used only when ALL of:
     *     1. P is visible (recursion-aware entity restriction), and
     *     2. there is a grant G with G.users_id = U, G visible to the session (Grant::visibilityCriteria()), G held
     *        (status active / revoke_pending / modify_pending) and G's resource not deleted, and
     *     3. P has a Position_Role cell, of any expectation (allowed / on_request / forbidden), on G's role, visible
     *        to the session (Position_Role::visibilityCriteria()).
     *   (2 and 3 are one correlated subquery: U IN (holders of such a grant whose role P has a cell on).) These are
     *   exactly the assignments MatrixBuilder needs to tell ok / forbidden_held from unexpected for the visible
     *   grants; an owner never receives the other positions of a person. A holder none of whose positions has a cell
     *   on any of their visible roles has no usable assignment: the owner page shows them in the bucket row, labelled
     *   "No position expects it" for owners.
     *
     * @return array<mixed>
     */
    private static function assignmentCriteria(): array
    {
        $t = Position_User::getTable();
        if (self::membersVisible()) {
            return [Position_User::visibilityCriteria()];
        }
        $pt = Position::getTable();
        $gt = Grant::getTable();
        $ct = Position_Role::getTable();
        $rt = Resource::getTable();
        return [
            "$t.plugin_iam_positions_id" => new QuerySubQuery(['SELECT' => "$pt.id", 'FROM' => $pt, 'WHERE' => self::positionCriteria()]),
            "$t.users_id" => new QuerySubQuery([
                'SELECT'     => "$gt.users_id",
                'FROM'       => $gt,
                'INNER JOIN' => [$ct => ['ON' => [$ct => 'plugin_iam_roles_id', $gt => 'plugin_iam_roles_id']]],
                'WHERE'      => [
                    Grant::visibilityCriteria(),
                    Position_Role::visibilityCriteria(),
                    "$gt.status"                   => MatrixBuilder::HELD_STATUSES,
                    "$gt.plugin_iam_resources_id"  => new QuerySubQuery(['SELECT' => "$rt.id", 'FROM' => $rt, 'WHERE' => ["$rt.is_deleted" => 0]]),
                    "$gt.users_id"                 => new QueryIdentifier("$t.users_id"),
                    "$ct.plugin_iam_positions_id"  => new QueryIdentifier("$t.plugin_iam_positions_id"),
                ],
            ]),
        ];
    }

    /**
     * Assignments that may still be active (PositionPeriod::isActive() decides).
     *
     * @return array<mixed>
     */
    private static function notEnded(string $today): array
    {
        $t = Position_User::getTable();
        return ['OR' => [["$t.date_end" => null], ["$t.date_end" => ['>=', $today]]]];
    }

    /**
     * @param array<mixed> $query
     * @return list<array<string,mixed>>
     */
    private static function fetch(array $query): array
    {
        global $DB;
        $rows = [];
        foreach ($DB->request($query) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }

    /**
     * The whole page model, one query per table.
     *
     * @return array<string,mixed>
     */
    public static function load(int $areaId, int $resourceId, bool $privileged, bool $onlyDeviations): array
    {
        $today = self::today();
        $rt = Resource::getTable();
        $rot = Role::getTable();
        $pt = Position::getTable();
        $ct = Position_Role::getTable();
        $ut = Position_User::getTable();
        $gt = Grant::getTable();

        // 1. Resources (all the visible ones feed the filter; the selected one, if any, is the only column)
        $resources = self::fetch([
            'SELECT' => ["$rt.id", "$rt.name"],
            'FROM'   => $rt,
            'WHERE'  => [Resource::visibilityCriteria(), "$rt.is_deleted" => 0],
            'ORDER'  => ["$rt.name", "$rt.id"],
        ]);
        $resourceName = [];
        foreach ($resources as $r) {
            $resourceName[(int) $r['id']] = (string) $r['name'];
        }
        $shown = $resourceId > 0 ? array_intersect_key($resourceName, [$resourceId => true]) : $resourceName;

        // 2. Roles of the shown resources, columns grouped by resource in resource order
        $roles = [];
        if ($shown !== []) {
            $where = [Role::visibilityCriteria(), "$rot.plugin_iam_resources_id" => array_keys($shown)];
            if ($privileged) {
                $where["$rot.level"] = 'privileged';
            }
            $order = array_flip(array_keys($shown));
            $roles = self::fetch([
                'SELECT' => ["$rot.id", "$rot.name", "$rot.level", "$rot.is_breakglass", "$rot.plugin_iam_resources_id"],
                'FROM'   => $rot,
                'WHERE'  => $where,
                'ORDER'  => ["$rot.name", "$rot.id"],
            ]);
            foreach ($roles as $i => $r) {
                $roles[$i]['resource_name'] = $shown[(int) $r['plugin_iam_resources_id']] ?? '';
            }
            usort($roles, static fn (array $a, array $b): int => $order[(int) $a['plugin_iam_resources_id']] <=> $order[(int) $b['plugin_iam_resources_id']]);
        }
        $roleIds = array_map(static fn (array $r): int => (int) $r['id'], $roles);

        // 3. Positions (recursion-aware entity restriction)
        $positions = self::fetch([
            'SELECT' => ["$pt.id", "$pt.name", "$pt.completename", "$pt.plugin_iam_positions_id", "$pt.is_active"],
            'FROM'   => $pt,
            'WHERE'  => self::positionCriteria(),
        ]);

        // 4-6. Cells, assignments and held grants
        $cells = $assignments = $grants = [];
        if ($roleIds !== []) {
            $cells = self::fetch([
                'SELECT' => ["$ct.plugin_iam_positions_id", "$ct.plugin_iam_roles_id", "$ct.expectation"],
                'FROM'   => $ct,
                'WHERE'  => [Position_Role::visibilityCriteria(), "$ct.plugin_iam_roles_id" => $roleIds],
            ]);
            $grants = self::fetch([
                'SELECT' => ["$gt.id", "$gt.users_id", "$gt.plugin_iam_roles_id", "$gt.status"],
                'FROM'   => $gt,
                'WHERE'  => [Grant::visibilityCriteria(), "$gt.status" => MatrixBuilder::HELD_STATUSES, "$gt.plugin_iam_roles_id" => $roleIds],
            ]);
        }
        $assignments = self::fetch([
            'SELECT' => ["$ut.plugin_iam_positions_id", "$ut.users_id", "$ut.date_begin", "$ut.date_end"],
            'FROM'   => $ut,
            'WHERE'  => [self::assignmentCriteria(), self::notEnded($today)],
        ]);

        $withData = [];
        foreach ($cells as $c) {
            $withData[(int) $c['plugin_iam_positions_id']] = true;
        }
        foreach ($assignments as $a) {
            $withData[(int) $a['plugin_iam_positions_id']] = true;
        }
        $tree = MatrixSummary::rows($positions, $withData, $areaId);
        $model = MatrixBuilder::build($tree['rows'], $roles, $cells, $assignments, $grants, $today);
        $without = MatrixBuilder::withoutPosition($roles, $assignments, $grants, $today);
        $summary = MatrixSummary::summarize($model, $without);
        $areas = $tree['areas'];
        $members = self::membersVisible();
        if (!$members) {
            // Asset owners: no 'missing' figures, and only the positions where they have something to see
            $summary = MatrixSummary::forOwner($summary);
            $kept = MatrixSummary::onlyRowsWithBlocks($model, $summary, $areas);
            $model = $kept['model'];
            $areas = $kept['areas'];
        }
        if ($onlyDeviations) {
            $model = MatrixSummary::onlyDeviations($model, $summary);
        }
        $breakglass = [];
        foreach ($roles as $r) {
            if ((int) $r['is_breakglass'] === 1) {
                $breakglass[(int) $r['id']] = true;
            }
        }

        return [
            'model'      => $model,
            'summary'    => $summary,
            'client'     => MatrixSummary::clientCells($model, $without, $members),
            'areas'      => $areas,
            'resources'  => $resourceName,
            'breakglass' => $breakglass,
        ];
    }

    /**
     * The people behind one cell (posId 0: the "No active position" row), or null when the session may not see the
     * position or the role's resource. Same predicates as the page.
     *
     * @return array<string,mixed>|null
     */
    public static function cell(int $positionId, int $roleId): ?array
    {
        if (!self::canView() || $positionId < 0) {
            return null;
        }
        $role = new Role();
        $resource = new Resource();
        if (
            !$role->getFromDB($roleId) || !$role->canViewItem()
            || !$resource->getFromDB((int) $role->fields['plugin_iam_resources_id']) || $resource->isDeleted()
        ) {
            return null;
        }
        $positionName = '';
        if ($positionId !== MatrixBuilder::NO_POSITION) {
            $position = new Position();
            if (
                !$position->getFromDB($positionId)
                || !Session::haveAccessToEntity((int) $position->fields['entities_id'], (int) $position->fields['is_recursive'] === 1)
            ) {
                return null;
            }
            $positionName = (string) $position->fields['completename'];
        }

        $today = self::today();
        $ct = Position_Role::getTable();
        $ut = Position_User::getTable();
        $gt = Grant::getTable();
        $grants = self::fetch([
            'SELECT' => ["$gt.id", "$gt.users_id", "$gt.plugin_iam_roles_id", "$gt.status", "$gt.tickets_id", "$gt.date_end"],
            'FROM'   => $gt,
            'WHERE'  => [Grant::visibilityCriteria(), "$gt.status" => MatrixBuilder::HELD_STATUSES, "$gt.plugin_iam_roles_id" => $roleId],
        ]);
        // The people of the row (or the holders for the bucket), with all their visible assignments
        if ($positionId === MatrixBuilder::NO_POSITION) {
            $people = array_values(array_unique(array_map(static fn (array $g): int => (int) $g['users_id'], $grants)));
        } else {
            // Same predicates as the page: only the assignments of the row the session may use, not ended
            $people = new QuerySubQuery([
                'SELECT' => "$ut.users_id",
                'FROM'   => $ut,
                'WHERE'  => [self::assignmentCriteria(), self::notEnded($today), "$ut.plugin_iam_positions_id" => $positionId],
            ]);
        }
        $assignments = $people === [] ? [] : self::fetch([
            'SELECT' => ["$ut.plugin_iam_positions_id", "$ut.users_id", "$ut.date_begin", "$ut.date_end"],
            'FROM'   => $ut,
            'WHERE'  => [self::assignmentCriteria(), self::notEnded($today), "$ut.users_id" => $people],
        ]);
        $cells = self::fetch([
            'SELECT' => ["$ct.plugin_iam_positions_id", "$ct.plugin_iam_roles_id", "$ct.expectation"],
            'FROM'   => $ct,
            'WHERE'  => [Position_Role::visibilityCriteria(), "$ct.plugin_iam_roles_id" => $roleId],
        ]);
        $roles = [[
            'id' => $roleId, 'name' => (string) $role->fields['name'], 'level' => (string) $role->fields['level'],
            'plugin_iam_resources_id' => (int) $resource->fields['id'], 'resource_name' => (string) $resource->fields['name'],
        ]];
        $key = $positionId . ':' . $roleId;
        if ($positionId === MatrixBuilder::NO_POSITION) {
            $built = MatrixBuilder::withoutPosition($roles, $assignments, $grants, $today);
        } else {
            $built = MatrixBuilder::build([['id' => $positionId, 'name' => $positionName]], $roles, $cells, $assignments, $grants, $today);
        }
        $counts = $built['cells'][$key] ?? ['expectation' => null, 'ok' => 0, 'expected' => 0, 'unexpected' => 0, 'forbidden_held' => 0];
        $members = self::membersVisible();

        return [
            'position'    => $positionName,
            'role'        => (string) $role->fields['name'],
            'level'       => (string) $role->fields['level'],
            'resource'    => (string) $resource->fields['name'],
            'expectation' => $counts['expectation'],
            'counts'      => MatrixSummary::clientCells(['cells' => [$key => $counts]], [], $members)[$key],
            'holders'     => self::describeHolders(MatrixSummary::visibleHolders($built['holders'][$key] ?? [], $members), $grants),
        ];
    }

    /**
     * Display data of the holders of a cell: name (with a link when the session may open that user), state, grant and
     * ticket (only when the session may see the ticket).
     *
     * @param list<array{users_id:int, state:string, grants_id:?int}> $holders
     * @param list<array<string,mixed>> $grants
     * @return list<array<string,mixed>>
     */
    private static function describeHolders(array $holders, array $grants): array
    {
        if ($holders === []) {
            return [];
        }
        $grantById = [];
        foreach ($grants as $g) {
            $grantById[(int) $g['id']] = $g;
        }
        $names = [];
        $ids = array_values(array_unique(array_map(static fn (array $h): int => $h['users_id'], $holders)));
        foreach (self::fetch(['SELECT' => ['id', 'name', 'realname', 'firstname'], 'FROM' => User::getTable(), 'WHERE' => ['id' => $ids]]) as $u) {
            $names[(int) $u['id']] = formatUserName((int) $u['id'], (string) $u['name'], (string) ($u['realname'] ?? ''), (string) ($u['firstname'] ?? ''));
        }
        $userVisible = [];
        foreach ($ids as $id) {
            $u = new User();
            $userVisible[$id] = $u->getFromDB($id) && $u->canViewItem();
        }
        $ticketVisible = [];
        $out = [];
        foreach ($holders as $h) {
            $gid = $h['grants_id'];
            $g = $gid !== null ? ($grantById[$gid] ?? null) : null;
            $ticket = (int) ($g['tickets_id'] ?? 0);
            if ($ticket > 0 && !isset($ticketVisible[$ticket])) {
                $t = new Ticket();
                $ticketVisible[$ticket] = $t->getFromDB($ticket) && $t->canViewItem();
            }
            $out[] = [
                'name'         => $names[$h['users_id']] ?? ('#' . $h['users_id']),
                'user_url'     => ($userVisible[$h['users_id']] ?? false) ? User::getFormURLWithID($h['users_id']) : '',
                'state'        => $h['state'],
                'grant'        => $g !== null ? (int) $g['id'] : 0,
                'grant_url'    => $g !== null ? Grant::getFormURLWithID((int) $g['id']) : '',
                'grant_status' => $g !== null ? (Grant::statusLabels()[(string) $g['status']] ?? (string) $g['status']) : '',
                'date_end'     => (string) ($g['date_end'] ?? ''),
                'ticket'       => $ticket > 0 && $ticketVisible[$ticket] ? $ticket : 0,
            ];
        }
        return $out;
    }

    /**
     * Snapshot of the session message queue, to be given to takeMessagesSince() after a call.
     *
     * @return array<mixed>
     */
    public static function messageQueue(): array
    {
        return (array) ($_SESSION['MESSAGE_AFTER_REDIRECT'] ?? []);
    }

    /**
     * The messages queued since the snapshot (e.g. a refusal of upsert()), as plain text. Only those are taken: the
     * queue is put back as it was in the snapshot, so unrelated messages still show up on the next page.
     *
     * @param array<mixed> $before
     */
    public static function takeMessagesSince(array $before): string
    {
        $own = self::messagesSince($before, self::messageQueue());
        $_SESSION['MESSAGE_AFTER_REDIRECT'] = $before;
        return implode(' ', $own);
    }

    /**
     * Messages of $after that are not in $before (same type), decoded to plain text (pure).
     *
     * @param array<mixed> $before
     * @param array<mixed> $after
     * @return list<string>
     */
    public static function messagesSince(array $before, array $after): array
    {
        $out = [];
        foreach ($after as $type => $list) {
            $old = array_values((array) ($before[$type] ?? []));
            foreach ((array) $list as $m) {
                if (in_array($m, $old, true)) {
                    continue;
                }
                $text = trim(strip_tags(html_entity_decode((string) $m, ENT_QUOTES | ENT_HTML5, 'UTF-8')));
                if ($text !== '') {
                    $out[] = $text;
                }
            }
        }
        return $out;
    }

    /**
     * Labels of the cell states (panel chips).
     *
     * @return array<string,string>
     */
    public static function stateLabels(): array
    {
        return [
            'ok'             => __('Holds it, as expected', 'iam'),
            'missing'        => __('Expected, not granted', 'iam'),
            'unexpected'     => __('Holds it, not expected', 'iam'),
            'forbidden_held' => __('Holds it, forbidden', 'iam'),
        ];
    }
}
