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
use Dropdown;
use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Iam\Install\Schema;
use Group;
use Glpi\DBAL\QuerySubQuery;
use Session;
use User;

/**
 * Resource (application, system, database...) whose accesses are governed. It points to an inventory item of a
 * whitelisted itemtype and has an owner (person and/or group), a criticality and a review frequency.
 */
class Resource extends CommonDBTM
{
    public static string $rightname = Rights::CONFIG;
    public bool $dohistory = true;

    public const CRITICALITIES = ['', 'low', 'medium', 'high', 'critical'];
    public const FREQUENCIES   = ['quarterly', 'semiannual', 'annual'];


    public static function getTypeName($nb = 0)
    {
        return _n('Resource', 'Resources', $nb, 'iam');
    }

    public static function getIcon()
    {
        return 'ti ti-apps';
    }

    public static function getMenuName()
    {
        return __('Resources', 'iam');
    }

    /** @return array<string,string> */
    public static function criticalityLabels(): array
    {
        return [
            ''         => '-',
            'low'      => __('Low', 'iam'),
            'medium'   => __('Medium', 'iam'),
            'high'     => __('High', 'iam'),
            'critical' => __('Critical', 'iam'),
        ];
    }

    /** @return array<string,string> */
    public static function frequencyLabels(): array
    {
        return [
            'quarterly'  => __('Quarterly', 'iam'),
            'semiannual' => __('Semiannual', 'iam'),
            'annual'     => __('Annual', 'iam'),
        ];
    }

    // Visibility: the catalogue (CONFIG READ) in the active entities; owners (ACCESS READ_OWNED) their own resources

    public static function canView(): bool
    {
        return (bool) Session::haveRight(Rights::CONFIG, READ) || (bool) Session::haveRight(Rights::ACCESS, READ_OWNED);
    }

    public function canViewItem(): bool
    {
        if (!$this->checkEntity(true)) {
            return false;
        }
        if (Session::haveRight(Rights::CONFIG, READ)) {
            return true;
        }
        return (bool) Session::haveRight(Rights::ACCESS, READ_OWNED)
            && Ownership::isOwner($this->fields, (int) Session::getLoginUserID(), self::sessionGroups());
    }

    /** @return list<int> */
    private static function sessionGroups(): array
    {
        return array_values(array_map('intval', (array) ($_SESSION['glpigroups'] ?? [])));
    }

    /**
     * Search restriction implementing canViewItem() in SQL (used for the notes of resources): resource visible in the
     * active entities (recursion-aware) and, without CONFIG READ, owned by the session (ACCESS READ_OWNED).
     *
     * @return array<mixed>
     */
    public static function visibilityCriteria(): array
    {
        $t = self::getTable();
        if (!self::canView()) {
            return ["$t.id" => 0];
        }
        $where = getEntitiesRestrictCriteria($t, '', '', true);
        if (self::ownedOnly()) {
            $where[] = Ownership::resourceCriteria((int) Session::getLoginUserID(), self::sessionGroups(), $t);
        }
        return $where;
    }

    /** True when the session sees the catalogue only through ownership. */
    public static function ownedOnly(): bool
    {
        return !Session::haveRight(Rights::CONFIG, READ);
    }

    /**
     * Resources of an inventory item that the session may see.
     *
     * @return list<array<string,mixed>>
     */
    public static function visibleFor(CommonDBTM $item): array
    {
        global $DB;
        $t = self::getTable();
        $where = [
            "$t.itemtype"   => $item->getType(),
            "$t.items_id"   => (int) $item->getID(),
            "$t.is_deleted" => 0,
        ] + getEntitiesRestrictCriteria($t, '', '', true);
        if (self::ownedOnly()) {
            $where[] = Ownership::resourceCriteria((int) Session::getLoginUserID(), self::sessionGroups(), $t);
        }
        $rows = [];
        foreach ($DB->request(['FROM' => $t, 'WHERE' => $where, 'ORDER' => ["$t.name", "$t.id"]]) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }

    // Nothing is deleted: a resource with grants, matrix cells or log entries can be trashed but never purged (purging
    // it would make its append-only log unreadable)

    /** Grants, matrix cells (directly or through its roles) and log entries that depend on the resource. */
    public static function dependencyCount(int $id): int
    {
        $roles = new QuerySubQuery([
            'SELECT' => 'id',
            'FROM'   => Role::getTable(),
            'WHERE'  => ['plugin_iam_resources_id' => $id],
        ]);
        return countElementsInTable(Schema::PREFIX . 'grants', ['OR' => ['plugin_iam_resources_id' => $id, 'plugin_iam_roles_id' => $roles]])
            + countElementsInTable(Schema::PREFIX . 'positions_roles', ['plugin_iam_roles_id' => $roles])
            + countElementsInTable(Schema::PREFIX . 'notes', NoteRules::targetCriteria(self::class, $id));
    }

    public function canPurgeItem(): bool
    {
        return parent::canPurgeItem() && self::dependencyCount((int) ($this->fields['id'] ?? 0)) === 0;
    }

    public function delete(array $input, $force = false, $history = true)
    {
        if ($force && self::dependencyCount((int) ($input['id'] ?? 0)) > 0) {
            Session::addMessageAfterRedirect(
                __('The resource has grants, matrix cells or log entries (nothing is deleted). Put it in the trashbin instead.', 'iam'),
                false,
                ERROR
            );
            return false;
        }
        return parent::delete($input, $force, $history);
    }

    /** The inventory item, or null when the itemtype is not allowed, the item does not exist or it is deleted. */
    public function linkedItem(): ?CommonDBTM
    {
        $type = (string) ($this->fields['itemtype'] ?? '');
        $id = (int) ($this->fields['items_id'] ?? 0);
        if ($id <= 0 || !ResourceItemtypes::isAllowed($type)) {
            return null;
        }
        $item = getItemForItemtype($type);
        if (!$item instanceof CommonDBTM || !$item->getFromDB($id)) {
            return null;
        }
        // Not every allowed type has the is_deleted field (e.g. Database is a child item)
        if ($item->maybeDeleted() && $item->isDeleted()) {
            return null;
        }
        return $item;
    }

    public function defineTabs($options = [])
    {
        $tabs = [];
        $this->addDefaultFormTab($tabs);
        $this->addStandardTab(Role::class, $tabs, $options);
        $this->addStandardTab(Grant::class, $tabs, $options);
        $this->addStandardTab(\Log::class, $tabs, $options);
        return $tabs;
    }

    public function rawSearchOptions()
    {
        $t = self::getTable();
        $tab = [['id' => 'common', 'name' => self::getTypeName(2)]];
        $tab[] = ['id' => 1, 'table' => $t, 'field' => 'name', 'name' => __('Name'), 'datatype' => 'itemlink', 'massiveaction' => false];
        $tab[] = ['id' => 2, 'table' => $t, 'field' => 'id', 'name' => __('ID'), 'datatype' => 'number', 'massiveaction' => false];
        $tab[] = ['id' => 3, 'table' => $t, 'field' => 'code', 'name' => __('Code', 'iam'), 'datatype' => 'string'];
        $tab[] = ['id' => 4, 'table' => $t, 'field' => 'itemtype', 'name' => __('Linked item type', 'iam'), 'datatype' => 'specific',
            'searchtype' => ['equals', 'notequals'], 'massiveaction' => false];
        $tab[] = ['id' => 5, 'table' => 'glpi_users', 'field' => 'name', 'linkfield' => 'users_id_owner', 'name' => __('Owner (person)', 'iam'),
            'datatype' => 'dropdown', 'right' => 'all', 'massiveaction' => false];
        $tab[] = ['id' => 6, 'table' => 'glpi_groups', 'field' => 'completename', 'linkfield' => 'groups_id_owner', 'name' => __('Owner (group)', 'iam'),
            'datatype' => 'dropdown', 'massiveaction' => false];
        $tab[] = ['id' => 7, 'table' => $t, 'field' => 'criticality', 'name' => __('Criticality', 'iam'), 'datatype' => 'specific',
            'searchtype' => ['equals', 'notequals']];
        $tab[] = ['id' => 8, 'table' => $t, 'field' => 'review_frequency', 'name' => __('Review frequency', 'iam'), 'datatype' => 'specific',
            'searchtype' => ['equals', 'notequals']];
        $tab[] = ['id' => 19, 'table' => $t, 'field' => 'date_mod', 'name' => __('Last update'), 'datatype' => 'datetime', 'massiveaction' => false];
        $tab[] = ['id' => 80, 'table' => 'glpi_entities', 'field' => 'completename', 'name' => \Entity::getTypeName(1), 'datatype' => 'dropdown',
            'massiveaction' => false];
        return $tab;
    }

    /** @return array<string,string> itemtype => label, in the order of the whitelist */
    public static function itemtypeLabels(): array
    {
        $out = [];
        foreach (ResourceItemtypes::ALLOWED as $type) {
            $out[$type] = $type::getTypeName(1);
        }
        return $out;
    }

    public static function getSpecificValueToDisplay($field, $values, array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        $v = (string) ($values[$field] ?? '');
        return match ($field) {
            'itemtype'         => htmlescape(ResourceItemtypes::isAllowed($v) ? $v::getTypeName(1) : $v),
            'criticality'      => htmlescape(self::criticalityLabels()[$v] ?? $v),
            'review_frequency' => htmlescape(self::frequencyLabels()[$v] ?? $v),
            default            => parent::getSpecificValueToDisplay($field, $values, $options),
        };
    }

    public static function getSpecificValueToSelect($field, $name = '', $values = '', array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        $map = ['itemtype' => self::itemtypeLabels(), 'criticality' => self::criticalityLabels(), 'review_frequency' => self::frequencyLabels()];
        if (isset($map[$field])) {
            return Dropdown::showFromArray($name, $map[$field], ['display' => false, 'value' => $values[$field] ?? '']);
        }
        return parent::getSpecificValueToSelect($field, $name, $values, $options);
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $linked = $this->linkedItem();
        $type = (string) ($this->fields['itemtype'] ?? '');
        $itemId = (int) ($this->fields['items_id'] ?? 0);
        // New resource opened from an inventory item (?itemtype=..&items_id=..): preset the link
        if ($this->isNewItem() && ResourceItemtypes::isAllowed((string) ($options['itemtype'] ?? ''))) {
            $type = (string) $options['itemtype'];
            $itemId = (int) ($options['items_id'] ?? 0);
        }
        if (!ResourceItemtypes::isAllowed($type)) {
            $type = '';
            $itemId = 0;
        }
        // The item (and so its name) is only handed to the dropdown when the session may see it
        $hidden = false;
        if ($itemId > 0 && !self::itemAllowed($type, $itemId)) {
            $hidden = $linked !== null || $this->isNewItem();
            $type = '';
            $itemId = 0;
        }
        $link = null;
        if ($linked !== null && $linked->can((int) $linked->getID(), READ)) {
            $link = ['name' => (string) $linked->getName(), 'url' => $linked->getFormURLWithID((int) $linked->getID())];
        }
        TemplateRenderer::getInstance()->display('@iam/resource_form.html.twig', [
            'item'          => $this,
            'params'        => $options,
            'itemtypes'     => array_keys(self::itemtypeLabels()),
            'preset_type'   => $type,
            'preset_id'     => $itemId,
            'criticalities' => self::criticalityLabels(),
            'frequencies'   => self::frequencyLabels(),
            'link'          => $link,
            'link_deleted'  => !$this->isNewItem() && (int) ($this->fields['items_id'] ?? 0) > 0 && $linked === null,
            'link_hidden'   => $hidden,
        ]);
        return true;
    }

    // Inventory tab

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || $item->isNewItem() || !ResourceItemtypes::isAllowed($item->getType()) || !self::canView()) {
            return '';
        }
        return self::createTabEntry(__('Access (IAM)', 'iam'), count(self::visibleFor($item)), null, self::getIcon());
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        // The tab loader calls this directly from the tab id: rights are checked here too
        if (!$item instanceof CommonDBTM || $item->isNewItem() || !ResourceItemtypes::isAllowed($item->getType()) || !self::canView() || !$item->canViewItem()) {
            return false;
        }
        $rows = [];
        foreach (self::visibleFor($item) as $r) {
            $grants = countElementsInTable(Schema::PREFIX . 'grants', ['plugin_iam_resources_id' => $r['id']]);
            $rows[] = [
                'id'          => $r['id'],
                'name'        => $r['name'],
                'code'        => $r['code'],
                'url'         => self::getFormURLWithID((int) $r['id']),
                'criticality' => self::criticalityLabels()[$r['criticality']] ?? $r['criticality'],
                'owner'       => (int) $r['users_id_owner'] > 0 ? User::getFriendlyNameById((int) $r['users_id_owner']) : '',
                'group'       => (int) $r['groups_id_owner'] > 0 ? Dropdown::getDropdownName(Group::getTable(), (int) $r['groups_id_owner']) : '',
                'roles'       => countElementsInTable(Role::getTable(), ['plugin_iam_resources_id' => $r['id']]),
                'grants'      => $grants,
            ];
        }
        TemplateRenderer::getInstance()->display('@iam/resource_item_tab.html.twig', [
            'rows'    => $rows,
            'can_add' => self::canCreate() && $item->canUpdateItem(),
            'add_url' => self::getFormURL() . '?itemtype=' . rawurlencode($item->getType()) . '&items_id=' . (int) $item->getID(),
        ]);
        return true;
    }

    // Input validation

    private static function fail(string $message): false
    {
        Session::addMessageAfterRedirect($message, false, ERROR);
        return false;
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    private static function sanitize(array $input, bool $isUpdate): array
    {
        // Internal keys of GLPI (_no_history, _glpi_csrf_token...) are not data fields
        $internal = array_filter($input, static fn ($k): bool => str_starts_with((string) $k, '_'), ARRAY_FILTER_USE_KEY);
        // The id identifies the row on update only
        $id = $isUpdate && isset($input['id']) ? ['id' => (int) $input['id']] : [];
        return InputGuard::filter($input, FieldSets::RESOURCE, FieldSets::RESOURCE_IMMUTABLE, $isUpdate) + $id + $internal;
    }

    /** The inventory item must exist, not be deleted and be viewable by the session (entity included). */
    private static function itemAllowed(string $type, int $id): bool
    {
        if (!ResourceItemtypes::isAllowed($type) || $id <= 0) {
            return false;
        }
        $item = getItemForItemtype($type);
        if (!$item instanceof CommonDBTM || !$item->getFromDB($id)) {
            return false;
        }
        if ($item->maybeDeleted() && $item->isDeleted()) {
            return false;
        }
        return $item->can($id, READ);
    }

    private static function ownerUserAllowed(int $id): bool
    {
        $user = new User();
        return $user->getFromDB($id) && Position_User::userVisible($id);
    }

    private static function ownerGroupAllowed(int $id): bool
    {
        $group = new Group();
        return $group->getFromDB($id)
            && Session::haveAccessToEntity((int) $group->fields['entities_id'], (int) ($group->fields['is_recursive'] ?? 0) === 1);
    }

    /**
     * Validation shared by add and update. $current holds the stored values on update.
     *
     * @param array<string,mixed> $input
     * @param array<string,mixed> $current
     * @return array<string,mixed>|false
     */
    private function validate(array $input, array $current, bool $isUpdate): array|false
    {
        if (array_key_exists('name', $input) || !$isUpdate) {
            $input['name'] = trim((string) ($input['name'] ?? ''));
            if ($input['name'] === '') {
                return self::fail(__('The resource must have a name.', 'iam'));
            }
        }
        if (array_key_exists('criticality', $input) && !InputGuard::enum((string) $input['criticality'], self::CRITICALITIES)) {
            return self::fail(__('The criticality is not valid.', 'iam'));
        }
        if (array_key_exists('review_frequency', $input) && !InputGuard::enum((string) $input['review_frequency'], self::FREQUENCIES)) {
            return self::fail(__('The review frequency is not valid.', 'iam'));
        }
        if (array_key_exists('is_recursive', $input)) {
            $input['is_recursive'] = empty($input['is_recursive']) ? 0 : 1;
        }

        // An empty link in the form means "not changed" (the item may be hidden from this viewer): no silent unlink
        if ($isUpdate && (string) ($input['itemtype'] ?? '') === '' && (int) ($input['items_id'] ?? 0) === 0) {
            unset($input['itemtype'], $input['items_id']);
        }

        // Linked item (revalidated only when it changes, so an old link to a deleted item does not block other edits)
        $type = (string) ($input['itemtype'] ?? ($current['itemtype'] ?? ''));
        $itemId = (int) ($input['items_id'] ?? ($current['items_id'] ?? 0));
        $changed = !$isUpdate
            || $type !== (string) ($current['itemtype'] ?? '')
            || $itemId !== (int) ($current['items_id'] ?? 0);
        if ($changed && !($type === '' && $itemId === 0)) {
            if (!ResourceItemtypes::isAllowed($type)) {
                return self::fail(__('The linked item type is not allowed.', 'iam'));
            }
            if (!self::itemAllowed($type, $itemId)) {
                return self::fail(__('The linked item does not exist or you are not allowed to see it.', 'iam'));
            }
        }
        if ($changed) {
            $input['itemtype'] = $type;
            $input['items_id'] = $itemId;
        }

        foreach (['users_id_owner' => 'ownerUserAllowed', 'groups_id_owner' => 'ownerGroupAllowed'] as $field => $check) {
            if (!array_key_exists($field, $input)) {
                continue;
            }
            $id = (int) $input[$field];
            $input[$field] = $id;
            if ($id > 0 && $id !== (int) ($current[$field] ?? 0) && !self::$check($id)) {
                return self::fail(__('The owner does not exist or you are not allowed to see it.', 'iam'));
            }
        }
        return $input;
    }

    public function prepareInputForAdd($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $input = $this->validate(self::sanitize($input, false), [], false);
        if ($input === false) {
            return false;
        }
        $input['review_frequency'] ??= 'annual';
        return $input;
    }

    public function prepareInputForUpdate($input)
    {
        if (!is_array($input)) {
            return false;
        }
        return $this->validate(self::sanitize($input, true), $this->fields, true);
    }
}
