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

use CommonDBChild;
use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Iam\Install\Schema;
use Session;

/**
 * Application role of a resource (e.g. "reader", "approver", "admin"): the unit that is granted and expected by position.
 */
class Role extends CommonDBChild
{
    public static string $itemtype = Resource::class;
    public static string $items_id = 'plugin_iam_resources_id';
    public static string $rightname = Rights::CONFIG;
    public bool $dohistory = true;

    public const LEVELS = ['standard', 'sensitive', 'privileged'];


    public static function getTypeName($nb = 0)
    {
        return _n('Role', 'Roles', $nb, 'iam');
    }

    public static function getIcon()
    {
        return 'ti ti-user-shield';
    }

    /** @return array<string,string> */
    public static function levelLabels(): array
    {
        return [
            'standard'   => __('Standard', 'iam'),
            'sensitive'  => __('Sensitive', 'iam'),
            'privileged' => __('Privileged', 'iam'),
        ];
    }

    /**
     * The roles table has no is_recursive column (the parent's recursion is not copied): without this GLPI builds
     * list queries (API, search) on a column that does not exist.
     */
    public function maybeRecursive()
    {
        return false;
    }

    /** Owners (READ_OWNED) see the roles of their resources: visibility follows the parent resource. */
    public static function canView(): bool
    {
        return Resource::canView();
    }

    public function canViewItem(): bool
    {
        $resource = new Resource();
        return $resource->getFromDB((int) ($this->fields['plugin_iam_resources_id'] ?? 0)) && $resource->canViewItem();
    }

    // Nothing is deleted: a role with grants or matrix cells is never purged

    public static function dependencyCount(int $id): int
    {
        return countElementsInTable(Schema::PREFIX . 'grants', ['plugin_iam_roles_id' => $id])
            + countElementsInTable(Schema::PREFIX . 'positions_roles', ['plugin_iam_roles_id' => $id]);
    }

    public function canPurgeItem(): bool
    {
        return parent::canPurgeItem() && self::dependencyCount((int) ($this->fields['id'] ?? 0)) === 0;
    }

    public function delete(array $input, $force = false, $history = true)
    {
        if (self::dependencyCount((int) ($input['id'] ?? 0)) > 0) {
            Session::addMessageAfterRedirect(
                __('The role has grants or matrix cells (nothing is deleted).', 'iam'),
                false,
                ERROR
            );
            return false;
        }
        return parent::delete($input, $force, $history);
    }

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
        $internal = array_filter($input, static fn ($k): bool => str_starts_with((string) $k, '_'), ARRAY_FILTER_USE_KEY);
        $id = $isUpdate && isset($input['id']) ? ['id' => (int) $input['id']] : [];
        return InputGuard::filter($input, FieldSets::ROLE, FieldSets::ROLE_IMMUTABLE, $isUpdate) + $id + $internal;
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>|false
     */
    private static function validate(array $input, bool $isUpdate): array|false
    {
        if (array_key_exists('name', $input) || !$isUpdate) {
            $input['name'] = trim((string) ($input['name'] ?? ''));
            if ($input['name'] === '') {
                return self::fail(__('The role must have a name.', 'iam'));
            }
        }
        if (!$isUpdate) {
            $input['level'] ??= 'standard';
        }
        if (array_key_exists('level', $input) && !InputGuard::enum((string) $input['level'], self::LEVELS)) {
            return self::fail(__('The role level is not valid.', 'iam'));
        }
        if (array_key_exists('is_breakglass', $input) || !$isUpdate) {
            $input['is_breakglass'] = empty($input['is_breakglass']) ? 0 : 1;
        }
        return $input;
    }

    public function prepareInputForAdd($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $input = self::validate(self::sanitize($input, false), false);
        if ($input === false) {
            return false;
        }
        $resource = new Resource();
        if (!$resource->getFromDB((int) ($input['plugin_iam_resources_id'] ?? 0)) || $resource->isDeleted()) {
            return self::fail(__('The resource of the role is not valid.', 'iam'));
        }
        // The entity is always the one of the resource, never taken from the request
        $input['entities_id'] = (int) $resource->fields['entities_id'];
        return parent::prepareInputForAdd($input);
    }

    public function prepareInputForUpdate($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $input = self::validate(self::sanitize($input, true), true);
        if ($input === false) {
            return false;
        }
        return parent::prepareInputForUpdate($input);
    }

    /** @return list<array<string,mixed>> */
    private static function rowsOf(Resource $resource): array
    {
        global $DB;
        $rows = [];
        foreach ($DB->request(['FROM' => self::getTable(), 'WHERE' => ['plugin_iam_resources_id' => $resource->getID()], 'ORDER' => ['name', 'id']]) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof Resource || $item->isNewItem() || !$item->canViewItem()) {
            return '';
        }
        return self::createTabEntry(self::getTypeName(Session::getPluralNumber()), count(self::rowsOf($item)), null, self::getIcon());
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        // The tab loader calls this directly from the tab id: rights are checked here too
        if (!$item instanceof Resource || $item->isNewItem() || !self::canView() || !$item->canViewItem()) {
            return false;
        }
        $rows = [];
        foreach (self::rowsOf($item) as $r) {
            $r['dependencies'] = self::dependencyCount((int) $r['id']);
            $rows[] = $r;
        }
        TemplateRenderer::getInstance()->display('@iam/roles_tab.html.twig', [
            'rows'      => $rows,
            'levels'    => self::levelLabels(),
            'resource'  => (int) $item->getID(),
            'can_add'   => self::canCreate() && $item->canUpdateItem() && !$item->isDeleted(),
            'can_edit'  => self::canUpdate() && $item->canUpdateItem(),
            'can_purge' => self::canPurge() && $item->canUpdateItem(),
            'action'    => self::getFormURL(),
        ]);
        return true;
    }
}
