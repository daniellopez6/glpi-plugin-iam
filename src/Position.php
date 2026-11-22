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

use CommonTreeDropdown;
use Session;

/**
 * Position (puesto) of the organization: configurable tree, optionally linked to a GLPI job title and group.
 */
class Position extends CommonTreeDropdown
{
    public static string $rightname = Rights::CONFIG;
    public bool $dohistory = true;
    public bool $can_be_translated = false;

    public static function getTypeName($nb = 0)
    {
        return _n('Position', 'Positions', $nb, 'iam');
    }

    public static function getIcon()
    {
        return 'ti ti-sitemap';
    }

    public static function getMenuName()
    {
        return __('Positions', 'iam');
    }

    /** @return array<int, array<string, mixed>> */
    public function getAdditionalFields()
    {
        return array_merge(parent::getAdditionalFields(), [
            ['name' => 'usertitles_id', 'label' => __('Job title', 'iam'), 'type' => 'dropdownValue', 'list' => true],
            ['name' => 'groups_id', 'label' => __('Group'), 'type' => 'dropdownValue', 'list' => true],
            ['name' => 'is_active', 'label' => __('Active'), 'type' => 'bool'],
        ]);
    }

    public function rawSearchOptions()
    {
        $tab = parent::rawSearchOptions();
        $tab[] = ['id' => 101, 'table' => $this->getTable(), 'field' => 'is_active', 'name' => __('Active'), 'datatype' => 'bool'];
        $tab[] = ['id' => 102, 'table' => 'glpi_usertitles', 'field' => 'name', 'name' => __('Job title', 'iam'), 'datatype' => 'dropdown'];
        $tab[] = ['id' => 103, 'table' => 'glpi_groups', 'field' => 'completename', 'name' => __('Group'), 'datatype' => 'dropdown'];
        return $tab;
    }

    /** The parent must be visible to the session and in the child's entity or a recursive ancestor of it. */
    private function parentRefused(int $parentId, int $childEntity): bool
    {
        if ($parentId <= 0) {
            return false;
        }
        $parent = new self();
        if (
            !$parent->getFromDB($parentId) || !$parent->canViewItem()
            || !PositionScope::parentAllowed(
                (int) $parent->fields['entities_id'],
                (int) $parent->fields['is_recursive'] === 1,
                $childEntity,
                array_keys(getAncestorsOf('glpi_entities', $childEntity))
            )
        ) {
            Session::addMessageAfterRedirect(__('The parent position does not exist or is not available in this entity.', 'iam'), false, ERROR);
            return true;
        }
        return false;
    }

    public function prepareInputForAdd($input)
    {
        if (!is_array($input)) {
            return false;
        }
        if ($this->parentRefused((int) ($input[self::getForeignKeyField()] ?? 0), (int) ($input['entities_id'] ?? 0))) {
            return false;
        }
        return parent::prepareInputForAdd($input);
    }

    public function prepareInputForUpdate($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $fk = self::getForeignKeyField();
        if (isset($input[$fk]) || isset($input['entities_id'])) {
            $parentId = (int) ($input[$fk] ?? $this->fields[$fk]);
            $entity = (int) ($input['entities_id'] ?? $this->fields['entities_id']);
            $changed = $parentId !== (int) $this->fields[$fk] || $entity !== (int) $this->fields['entities_id'];
            if ($changed && $this->parentRefused($parentId, $entity)) {
                return false;
            }
        }
        return parent::prepareInputForUpdate($input);
    }

    /** Number of assignments (active or ended) of a position. */
    public static function assignmentCount(int $id): int
    {
        return countElementsInTable(Position_User::getTable(), ['plugin_iam_positions_id' => $id]);
    }

    /** A position with assignment history is never purged; it can be deactivated instead. */
    public function canPurgeItem(): bool
    {
        return parent::canPurgeItem() && self::assignmentCount((int) ($this->fields['id'] ?? 0)) === 0;
    }

    public function pre_deleteItem()
    {
        if (self::assignmentCount((int) $this->getID()) > 0) {
            Session::addMessageAfterRedirect(
                __('The position has assignments (the history is kept). Deactivate it instead of deleting it.', 'iam'),
                false,
                ERROR
            );
            return false;
        }
        return parent::pre_deleteItem();
    }
}
