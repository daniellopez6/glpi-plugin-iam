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

use CommonDBTM;
use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;
use Glpi\DBAL\QuerySubQuery;
use Html;
use Profile;
use Profile_User;
use Session;
use User;

/**
 * Permanent note ("log") on a grant, a resource or a position assignment (spec §7). Append-only in every layer:
 * no update, delete or purge from the class, the UI, the API or the massive actions, not even for Super-Admin.
 * A correction is a new note that references the corrected one (on the same target). The GLPI Notepad is not used.
 *
 * Rights:
 * - read: whoever can see the target (target->canViewItem()); lists use visibilityCriteria(), the same predicate;
 * - add:  whoever can see the target and has ACCESS CREATE, or ACCESS UPDATE_OWNED and owns the resource of the
 *         target (grants and resources only: position assignments need CREATE);
 * - update/delete/purge: never.
 */
class Note extends CommonDBTM
{
    public static string $rightname = Rights::ACCESS;
    // Nothing ever changes: there is no history to keep
    public bool $dohistory = false;

    public static function getTypeName($nb = 0)
    {
        return _n('Log entry', 'Log entries', $nb, 'iam');
    }

    public static function getIcon()
    {
        return 'ti ti-notebook';
    }

    /**
     * Visibility follows the target, not the note's own entity column (a copy of the target's): a note on a grant of a
     * recursive resource of a parent entity is visible from the child entities, like the grant itself. GLPI's generic
     * entity filter would only compare the note's entities_id, so it is disabled and replaced by visibilityCriteria()
     * (addDefaultWhere hook) and canViewItem(), which implement the same predicate.
     */
    public function isEntityAssign()
    {
        return false;
    }

    public function maybeRecursive()
    {
        return false;
    }

    public function getEntityID()
    {
        return (int) ($this->fields['entities_id'] ?? -1);
    }

    // Global rights

    public static function canView(): bool
    {
        return Grant::canView() || Resource::canView() || Position_User::canView();
    }

    public static function canCreate(): bool
    {
        return (bool) Session::haveRightsOr(self::$rightname, [CREATE, UPDATE_OWNED]);
    }

    public static function canUpdate(): bool
    {
        return false;
    }

    public static function canDelete(): bool
    {
        return false;
    }

    public static function canPurge(): bool
    {
        return false;
    }

    // Targets

    /**
     * The target of a note, resolved only from the whitelist (never instantiated from an unchecked itemtype).
     */
    public static function loadTarget(mixed $itemtype, mixed $itemsId): ?CommonDBTM
    {
        if (!NoteRules::isTarget($itemtype) || !is_numeric($itemsId) || (int) $itemsId <= 0) {
            return null;
        }
        $target = getItemForItemtype($itemtype);
        return $target instanceof CommonDBTM && $target->getFromDB((int) $itemsId) ? $target : null;
    }

    private static function isTargetItem(CommonGLPI $item): bool
    {
        return in_array($item::class, NoteRules::TARGETS, true);
    }

    /**
     * Resource row of a grant or a resource target (owner case), null otherwise.
     *
     * @return array<string,mixed>|null
     */
    private static function resourceOf(CommonDBTM $target): ?array
    {
        if ($target instanceof Resource) {
            return $target->fields;
        }
        if ($target instanceof Grant) {
            $resource = new Resource();
            return $resource->getFromDB((int) $target->fields['plugin_iam_resources_id']) ? $resource->fields : null;
        }
        return null;
    }

    /** May the session add a note on this target? */
    public static function mayAddOn(CommonDBTM $target): bool
    {
        if (!self::isTargetItem($target) || $target->isNewItem() || !$target->canViewItem()) {
            return false;
        }
        if (Session::haveRight(self::$rightname, CREATE)) {
            return true;
        }
        if (!Session::haveRight(self::$rightname, UPDATE_OWNED)) {
            return false;
        }
        $resource = self::resourceOf($target);
        return $resource !== null && Ownership::isOwner($resource, (int) Session::getLoginUserID(), Rights::currentGroupIds());
    }

    // Item rights

    public function canViewItem(): bool
    {
        $target = self::loadTarget($this->fields['itemtype'] ?? null, $this->fields['items_id'] ?? 0);
        return $target !== null && $target->canViewItem();
    }

    public function canCreateItem(): bool
    {
        if (!self::canCreate()) {
            return false;
        }
        $target = self::loadTarget($this->input['itemtype'] ?? null, $this->input['items_id'] ?? 0);
        return $target !== null && self::mayAddOn($target);
    }

    public function canUpdateItem(): bool
    {
        return false;
    }

    public function canDeleteItem(): bool
    {
        return false;
    }

    public function canPurgeItem(): bool
    {
        return false;
    }

    // Append-only: every write path other than add is refused

    public function update(array $input, $history = true, $options = [])
    {
        return false;
    }

    public function delete(array $input, $force = false, $history = true)
    {
        return false;
    }

    public function prepareInputForUpdate($input)
    {
        Session::addMessageAfterRedirect(self::errorMessage('append_only'), false, ERROR);
        return false;
    }

    public function pre_deleteItem()
    {
        return false;
    }

    /** @return list<string> */
    public function getForbiddenStandardMassiveAction()
    {
        $forbidden = parent::getForbiddenStandardMassiveAction();
        foreach (['update', 'delete', 'purge', 'restore', 'clone', 'add_transfer_list', 'amend_comment', 'add_note'] as $action) {
            $forbidden[] = $action;
        }
        return $forbidden;
    }

    /** @return list<string> */
    public function getForbiddenSingleMassiveActions()
    {
        return array_merge(parent::getForbiddenSingleMassiveActions(), ['*:update', '*:delete', '*:purge', '*:clone']);
    }

    // Add

    public static function errorMessage(string $code): string
    {
        return match ($code) {
            'target_invalid'    => __('The item does not exist or you are not allowed to add a log entry to it.', 'iam'),
            'content_empty'     => __('The log entry is empty.', 'iam'),
            'content_too_long'  => sprintf(__('The log entry is too long (maximum %d characters).', 'iam'), NoteRules::MAX_LENGTH),
            'reference_invalid' => __('The corrected entry does not exist or belongs to another item.', 'iam'),
            'append_only'       => __('Log entries cannot be changed or deleted. Add a correction instead.', 'iam'),
            default             => __('The log entry is not valid.', 'iam'),
        };
    }

    private static function fail(string $code): false
    {
        Session::addMessageAfterRedirect(self::errorMessage($code), false, ERROR);
        return false;
    }

    public function prepareInputForAdd($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $errors = NoteRules::errors($input);
        if ($errors !== []) {
            return self::fail($errors[0]);
        }
        $data = NoteRules::prepareAdd($input, (int) Session::getLoginUserID(), (string) ($_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s')));
        if ($data === false) {
            return self::fail('invalid');
        }
        // Rights again here (defence in depth: the API and the form already called canCreateItem())
        $target = self::loadTarget($data['itemtype'], $data['items_id']);
        if ($target === null || !self::mayAddOn($target)) {
            return self::fail('target_invalid');
        }
        if ($data['plugin_iam_notes_id'] > 0) {
            $ref = new self();
            if (!$ref->getFromDB($data['plugin_iam_notes_id']) || !NoteRules::sameTarget($ref->fields, $data['itemtype'], $data['items_id'])) {
                return self::fail('reference_invalid');
            }
        }
        // The entity is always the target's
        $data['entities_id'] = (int) ($target->fields['entities_id'] ?? 0);
        return $data;
    }

    // Visibility in lists

    /**
     * Search/API restriction implementing canViewItem() in SQL: the note's target is visible to the session, with the
     * visibility predicate of each target type (Grant::visibilityCriteria(), Resource::visibilityCriteria(),
     * Position_User::visibilityCriteria()), combined with OR by itemtype. No visible target type: nothing.
     *
     * @return array<mixed>
     */
    public static function visibilityCriteria(): array
    {
        $t = self::getTable();
        $sources = [
            Grant::class         => [Grant::canView(), Grant::getTable(), Grant::visibilityCriteria(...)],
            Resource::class      => [Resource::canView(), Resource::getTable(), Resource::visibilityCriteria(...)],
            Position_User::class => [Position_User::canView(), Position_User::getTable(), Position_User::visibilityCriteria(...)],
        ];
        $or = [];
        foreach ($sources as $itemtype => [$allowed, $table, $criteria]) {
            if (!$allowed) {
                continue;
            }
            $or[] = [
                "$t.itemtype" => $itemtype,
                "$t.items_id" => new QuerySubQuery(['SELECT' => "$table.id", 'FROM' => $table, 'WHERE' => [$criteria()]]),
            ];
        }
        return $or === [] ? ["$t.id" => 0] : ['OR' => $or];
    }

    // Search (API): read-only options

    public function rawSearchOptions()
    {
        $t = self::getTable();
        $tab = [['id' => 'common', 'name' => self::getTypeName(2)]];
        $tab[] = ['id' => 2, 'table' => $t, 'field' => 'id', 'name' => __('ID'), 'datatype' => 'number', 'massiveaction' => false];
        $tab[] = ['id' => 3, 'table' => $t, 'field' => 'itemtype', 'name' => __('Item type', 'iam'), 'datatype' => 'specific',
            'searchtype' => ['equals', 'notequals'], 'massiveaction' => false];
        $tab[] = ['id' => 4, 'table' => $t, 'field' => 'items_id', 'name' => __('Item', 'iam'), 'datatype' => 'number', 'massiveaction' => false];
        $tab[] = ['id' => 5, 'table' => $t, 'field' => 'content', 'name' => __('Content', 'iam'), 'datatype' => 'text', 'massiveaction' => false];
        $tab[] = ['id' => 6, 'table' => 'glpi_users', 'field' => 'name', 'linkfield' => 'users_id', 'name' => __('Author', 'iam'),
            'datatype' => 'dropdown', 'right' => 'all', 'massiveaction' => false];
        $tab[] = ['id' => 7, 'table' => $t, 'field' => 'plugin_iam_notes_id', 'name' => __('Corrects entry', 'iam'), 'datatype' => 'number',
            'massiveaction' => false];
        $tab[] = ['id' => 121, 'table' => $t, 'field' => 'date_creation', 'name' => __('Creation date'), 'datatype' => 'datetime',
            'massiveaction' => false];
        $tab[] = ['id' => 80, 'table' => 'glpi_entities', 'field' => 'completename', 'name' => __('Entity'), 'datatype' => 'dropdown',
            'massiveaction' => false];
        return $tab;
    }

    /** @return array<string,string> */
    public static function targetLabels(): array
    {
        return [
            Grant::class         => Grant::getTypeName(1),
            Resource::class      => Resource::getTypeName(1),
            Position_User::class => Position_User::getTypeName(1),
        ];
    }

    public static function getSpecificValueToDisplay($field, $values, array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        if ($field === 'itemtype') {
            $v = (string) ($values[$field] ?? '');
            return htmlescape(self::targetLabels()[$v] ?? $v);
        }
        return parent::getSpecificValueToDisplay($field, $values, $options);
    }

    // Tab "Log (IAM)" on the targets

    private static function tabAllowed(CommonGLPI $item): bool
    {
        return $item instanceof CommonDBTM && self::isTargetItem($item) && !$item->isNewItem() && $item->canViewItem();
    }

    /**
     * Notes of a target, newest first (the caller checked that the target is visible).
     *
     * @return list<array<string,mixed>>
     */
    private static function rowsFor(CommonDBTM $item): array
    {
        global $DB;
        $t = self::getTable();
        $rows = [];
        foreach (
            $DB->request([
                'FROM'  => $t,
                'WHERE' => NoteRules::targetCriteria($item::class, (int) $item->getID()),
                'ORDER' => ["$t.date_creation DESC", "$t.id DESC"],
            ]) as $r
        ) {
            $rows[] = $r;
        }
        return $rows;
    }

    /**
     * Authors among the given users that hold the "IAM - Agente" role profile (badge only, no stored provenance).
     *
     * @param list<int> $userIds
     * @return array<int,true>
     */
    private static function agentAuthors(array $userIds): array
    {
        global $DB;
        if ($userIds === []) {
            return [];
        }
        $put = Profile_User::getTable();
        $pt = Profile::getTable();
        $agents = [];
        foreach (
            $DB->request([
                'SELECT'     => ["$put.users_id"],
                'DISTINCT'   => true,
                'FROM'       => $put,
                'INNER JOIN' => [$pt => ['ON' => [$put => 'profiles_id', $pt => 'id']]],
                'WHERE'      => ["$put.users_id" => $userIds, "$pt.comment" => ['LIKE', '%' . Rights::marker('agent') . '%']],
            ]) as $r
        ) {
            $agents[(int) $r['users_id']] = true;
        }
        return $agents;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || !self::tabAllowed($item)) {
            return '';
        }
        return self::createTabEntry(__('Log (IAM)', 'iam'), count(self::rowsFor($item)), null, self::getIcon());
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        // The tab loader calls this directly from the tab id: rights are checked here too
        if (!$item instanceof CommonDBTM || !self::tabAllowed($item)) {
            return false;
        }
        $raw = self::rowsFor($item);
        $agents = self::agentAuthors(array_values(array_unique(array_map(static fn (array $r): int => (int) $r['users_id'], $raw))));
        $rows = [];
        foreach ($raw as $r) {
            $uid = (int) $r['users_id'];
            $rows[] = [
                'id'       => (int) $r['id'],
                'author'   => (string) User::getFriendlyNameById($uid),
                'agent'    => isset($agents[$uid]),
                'date'     => (string) Html::convDateTime((string) $r['date_creation']),
                'content'  => (string) $r['content'],
                'corrects' => (int) $r['plugin_iam_notes_id'],
            ];
        }
        TemplateRenderer::getInstance()->display('@iam/notes_tab.html.twig', [
            'help'       => Help::context(),
            'rows'       => $rows,
            'can_add'    => self::mayAddOn($item),
            'itemtype'   => $item::class,
            'items_id'   => (int) $item->getID(),
            'max_length' => NoteRules::MAX_LENGTH,
            'action'     => plugin_iam_url('front/note.form.php'),
        ]);
        return true;
    }
}
