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

use CommonDBRelation;
use CommonDBTM;
use Session;

/**
 * Cell of the RBAC matrix: what a position is expected to have on a role (allowed, on request or forbidden).
 * Absence of a row means "no expectation". Cells are configuration: changing one back to "no expectation" removes
 * the row, and every add, change and removal is logged on both the position and the role.
 */
class Position_Role extends CommonDBRelation
{
    public static string $rightname = Rights::CONFIG;
    public bool $dohistory = true;

    public const EXPECTATIONS = ['allowed', 'on_request', 'forbidden'];

    public static ?string $itemtype_1 = Position::class;
    public static ?string $items_id_1 = 'plugin_iam_positions_id';
    public static ?string $itemtype_2 = Role::class;
    public static ?string $items_id_2 = 'plugin_iam_roles_id';
    public static int $checkItem_1_Rights = self::DONT_CHECK_ITEM_RIGHTS;
    public static int $checkItem_2_Rights = self::DONT_CHECK_ITEM_RIGHTS;
    public static bool $check_entity_coherency = false;
    // The change trail of the matrix lives on both sides
    public static bool $logs_for_item_1 = true;
    public static bool $logs_for_item_2 = true;

    public static function getTypeName($nb = 0)
    {
        return _n('Matrix cell', 'Matrix cells', $nb, 'iam');
    }

    public static function getIcon()
    {
        return 'ti ti-grid-dots';
    }

    /** @return array<string,string> */
    public static function expectationLabels(): array
    {
        return [
            'allowed'    => __('Allowed', 'iam'),
            'on_request' => __('On request', 'iam'),
            'forbidden'  => __('Forbidden', 'iam'),
        ];
    }

    /** The table has no is_recursive column. */
    public function maybeRecursive()
    {
        return false;
    }

    // Rights: CONFIG (CREATE / UPDATE). Removing a cell is "no expectation": it needs UPDATE and is never a PURGE.

    public static function canView(): bool
    {
        return Resource::canView();
    }

    public static function canCreate(): bool
    {
        return (bool) Session::haveRight(self::$rightname, CREATE);
    }

    public static function canUpdate(): bool
    {
        return (bool) Session::haveRight(self::$rightname, UPDATE);
    }

    public static function canDelete(): bool
    {
        return self::canUpdate();
    }

    public static function canPurge(): bool
    {
        return false;
    }

    /** Recursion-aware visibility of a position (own entity, or a recursive position of an ancestor entity). */
    private static function positionVisible(int $positionId): bool
    {
        $position = new Position();
        return $position->getFromDB($positionId)
            && Session::haveAccessToEntity((int) $position->fields['entities_id'], (int) $position->fields['is_recursive'] === 1);
    }

    /** The role's resource must be visible to the session (Resource::canViewItem). */
    private static function roleVisible(int $roleId): bool
    {
        $role = new Role();
        return $role->getFromDB($roleId) && $role->canViewItem();
    }

    /** Writing a cell needs write access on the role's resource (CONFIG UPDATE and an active entity, non-recursive). */
    private static function roleWritable(int $roleId): bool
    {
        $role = new Role();
        $resource = new Resource();
        return $role->getFromDB($roleId)
            && $resource->getFromDB((int) $role->fields['plugin_iam_resources_id'])
            && $resource->canUpdateItem();
    }

    private static function rowWritable(int $positionId, int $roleId): bool
    {
        return self::positionVisible($positionId) && self::roleWritable($roleId);
    }

    private static function rowVisible(int $positionId, int $roleId): bool
    {
        return self::positionVisible($positionId) && self::roleVisible($roleId);
    }

    public function canViewItem(): bool
    {
        return self::canView() && self::rowVisible((int) ($this->fields['plugin_iam_positions_id'] ?? 0), (int) ($this->fields['plugin_iam_roles_id'] ?? 0));
    }

    public function canCreateItem(): bool
    {
        return self::canCreate()
            && self::rowWritable((int) ($this->input['plugin_iam_positions_id'] ?? 0), (int) ($this->input['plugin_iam_roles_id'] ?? 0));
    }

    public function canUpdateItem(): bool
    {
        return self::canUpdate() && self::rowWritable((int) ($this->fields['plugin_iam_positions_id'] ?? 0), (int) ($this->fields['plugin_iam_roles_id'] ?? 0));
    }

    public function canDeleteItem(): bool
    {
        return self::canUpdateItem();
    }

    public function canPurgeItem(): bool
    {
        return false;
    }

    private static function fail(string $message): false
    {
        Session::addMessageAfterRedirect($message, false, ERROR);
        return false;
    }

    /** @return array<string,mixed>|null the existing cell */
    private static function findCell(int $positionId, int $roleId): ?array
    {
        global $DB;
        foreach ($DB->request(['FROM' => self::getTable(), 'WHERE' => ['plugin_iam_positions_id' => $positionId, 'plugin_iam_roles_id' => $roleId], 'LIMIT' => 1]) as $r) {
            return $r;
        }
        return null;
    }

    /** The history entries carry the expectation, so a removed cell still tells what it allowed. */
    private function historyName(CommonDBTM $other): string
    {
        $exp = (string) ($this->fields['expectation'] ?? $this->input['expectation'] ?? '');
        $label = self::expectationLabels()[$exp] ?? $exp;
        return $other->getNameID(['forceid' => true, 'additional' => true]) . ($label === '' ? '' : ' (' . $label . ')');
    }

    public function getHistoryNameForItem1(CommonDBTM $item, $case)
    {
        return $this->historyName($item);
    }

    public function getHistoryNameForItem2(CommonDBTM $item, $case)
    {
        return $this->historyName($item);
    }

    public function prepareInputForAdd($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $positionId = (int) ($input['plugin_iam_positions_id'] ?? 0);
        $roleId = (int) ($input['plugin_iam_roles_id'] ?? 0);
        $position = new Position();
        if (!$position->getFromDB($positionId) || $position->isDeleted()) {
            return self::fail(__('Select a position.', 'iam'));
        }
        $role = new Role();
        $resource = new Resource();
        if (
            !$role->getFromDB($roleId)
            || !$resource->getFromDB((int) $role->fields['plugin_iam_resources_id'])
            || $resource->isDeleted()
        ) {
            return self::fail(__('The role does not exist or its resource is in the trash.', 'iam'));
        }
        $expectation = (string) ($input['expectation'] ?? '');
        if (!InputGuard::enum($expectation, self::EXPECTATIONS)) {
            return self::fail(__('The expectation is not valid.', 'iam'));
        }
        if (self::findCell($positionId, $roleId) !== null) {
            return self::fail(__('The position already has an expectation for this role.', 'iam'));
        }
        $data = InputGuard::filter($input, FieldSets::POSITION_ROLE, FieldSets::POSITION_ROLE_IMMUTABLE, false);
        $data['plugin_iam_positions_id'] = $positionId;
        $data['plugin_iam_roles_id'] = $roleId;
        $data['expectation'] = $expectation;
        // The entity is always the one of the role's resource, never taken from the request
        $data['entities_id'] = (int) $resource->fields['entities_id'];
        return $data;
    }

    public function prepareInputForUpdate($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $id = isset($input['id']) ? ['id' => (int) $input['id']] : [];
        $data = InputGuard::filter($input, FieldSets::POSITION_ROLE, FieldSets::POSITION_ROLE_IMMUTABLE, true) + $id;
        if (array_key_exists('expectation', $data)) {
            $role = new Role();
            $resource = new Resource();
            if (
                !$role->getFromDB((int) $this->fields['plugin_iam_roles_id'])
                || !$resource->getFromDB((int) $role->fields['plugin_iam_resources_id'])
                || $resource->isDeleted()
            ) {
                return self::fail(__('The role does not exist or its resource is in the trash.', 'iam'));
            }
        }
        if (array_key_exists('expectation', $data) && !InputGuard::enum((string) $data['expectation'], self::EXPECTATIONS)) {
            return self::fail(__('The expectation is not valid.', 'iam'));
        }
        return $data;
    }

    /**
     * Sets the expectation of a position on a role. null or '' removes the cell (no expectation).
     * Applies the same rights checks as the form; returns false on any refusal.
     */
    public static function upsert(int $positionId, int $roleId, ?string $expectation): bool
    {
        // Rights first, whatever the branch: no answer about the existence of a cell without write access
        if (!self::canUpdate() || !self::rowWritable($positionId, $roleId)) {
            return false;
        }
        $existing = self::findCell($positionId, $roleId);
        $cell = new self();
        if ($expectation === null || $expectation === '') {
            if ($existing === null) {
                return true;
            }
            if (!$cell->getFromDB((int) $existing['id']) || !$cell->canDeleteItem()) {
                return false;
            }
            // Configuration, not an access record: the row goes, the log of both sides keeps the trail
            return (bool) $cell->delete(['id' => (int) $existing['id']], true);
        }
        if (!InputGuard::enum($expectation, self::EXPECTATIONS)) {
            return false;
        }
        if ($existing !== null) {
            if (!$cell->getFromDB((int) $existing['id']) || !$cell->canUpdateItem()) {
                return false;
            }
            if ((string) $existing['expectation'] === $expectation) {
                return true;
            }
            return (bool) $cell->update(['id' => (int) $existing['id'], 'expectation' => $expectation]);
        }
        $input = ['plugin_iam_positions_id' => $positionId, 'plugin_iam_roles_id' => $roleId, 'expectation' => $expectation];
        $cell->input = $input;
        if (!$cell->canCreateItem()) {
            return false;
        }
        return (int) $cell->add($input) > 0;
    }
}
