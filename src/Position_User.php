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
use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;
use Profile_User;
use Session;
use Ticket;
use User;

/**
 * Assignment of a person to a position (holder, substitute or temporary) with its validity period.
 * The history is kept: an assignment is closed by setting its end date, never deleted.
 */
class Position_User extends CommonDBRelation
{
    public static string $rightname = Rights::ACCESS;

    public static ?string $itemtype_1 = Position::class;
    public static ?string $items_id_1 = 'plugin_iam_positions_id';
    public static ?string $itemtype_2 = User::class;
    public static ?string $items_id_2 = 'users_id';
    public static int $checkItem_1_Rights = self::DONT_CHECK_ITEM_RIGHTS;
    public static int $checkItem_2_Rights = self::DONT_CHECK_ITEM_RIGHTS;
    public static bool $check_entity_coherency = false;

    public static function getTypeName($nb = 0)
    {
        return _n('Position assignment', 'Position assignments', $nb, 'iam');
    }

    public static function getIcon()
    {
        return 'ti ti-user-check';
    }

    /** @return array<string,string> */
    public static function typeLabels(): array
    {
        return [
            'holder'     => __('Holder', 'iam'),
            'substitute' => __('Substitute', 'iam'),
            'temporary'  => __('Temporary', 'iam'),
        ];
    }

    // Rights: ACCESS (CREATE to add, UPDATE to edit). Assignments are history: never deleted nor purged.
    // UPDATE_OWNED is deliberately not enough: it only covers the accesses of owned resources, and who holds a
    // position drives the access that is expected from them.

    public static function canView(): bool
    {
        return (bool) Session::haveRight(self::$rightname, READ);
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
        return false;
    }

    public static function canPurge(): bool
    {
        return false;
    }

    public function canViewItem(): bool
    {
        return self::canView() && Session::haveAccessToEntity((int) ($this->fields['entities_id'] ?? 0));
    }

    public function canCreateItem(): bool
    {
        $position = new Position();
        if (!self::canCreate() || !$position->getFromDB((int) ($this->input['plugin_iam_positions_id'] ?? 0))) {
            return false;
        }
        if (!self::userVisible((int) ($this->input['users_id'] ?? 0))) {
            return false;
        }
        return Session::haveAccessToEntity((int) $position->fields['entities_id']);
    }

    public function canUpdateItem(): bool
    {
        return self::canUpdate() && Session::haveAccessToEntity((int) ($this->fields['entities_id'] ?? 0));
    }

    public function canDeleteItem(): bool
    {
        return false;
    }

    public function canPurgeItem(): bool
    {
        return false;
    }

    /** User-facing message of a PositionPeriod::validate() error code. */
    public static function errorMessage(string $code): string
    {
        return match ($code) {
            'date_order'        => __('The end date cannot be before the begin date.', 'iam'),
            'date_invalid'      => __('A date is not valid (expected format YYYY-MM-DD).', 'iam'),
            'primary_duplicate' => __('The person already has an active primary position.', 'iam'),
            'type_invalid'      => __('The assignment type is not valid.', 'iam'),
            default             => __('The assignment is not valid.', 'iam'),
        };
    }

    private static function fail(string $message): false
    {
        Session::addMessageAfterRedirect($message, false, ERROR);
        return false;
    }

    /**
     * Rows of the person other than the one being edited.
     *
     * @return list<array<string,mixed>>
     */
    private static function otherRows(int $usersId, int $exceptId): array
    {
        global $DB;
        $rows = [];
        foreach ($DB->request(['FROM' => self::getTable(), 'WHERE' => ['users_id' => $usersId, 'id' => ['<>', $exceptId]]]) as $r) {
            $rows[] = $r;
        }
        return $rows;
    }

    private static function userVisible(int $usersId): bool
    {
        $entities = Profile_User::getUserEntities($usersId, true);
        return $entities !== [] && Session::haveAccessToOneOfEntities($entities);
    }

    /** The ticket, when given, must exist and be visible to the current user. */
    private static function ticketAllowed(int $ticketId): bool
    {
        if ($ticketId <= 0) {
            return true;
        }
        $ticket = new Ticket();
        return $ticket->getFromDB($ticketId) && $ticket->canViewItem();
    }

    /**
     * @param array<string,mixed> $data
     * @return array<string,mixed>
     */
    private static function cleanDates(array $data): array
    {
        foreach (['date_begin', 'date_end'] as $f) {
            if (array_key_exists($f, $data)) {
                $v = trim((string) $data[$f]);
                $data[$f] = $v === '' ? null : $v;
            }
        }
        return $data;
    }

    public function prepareInputForAdd($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $position = new Position();
        if (!$position->getFromDB((int) ($input['plugin_iam_positions_id'] ?? 0))) {
            return self::fail(__('Select a position.', 'iam'));
        }
        if ((int) $position->fields['is_active'] !== 1) {
            return self::fail(__('The position is not active.', 'iam'));
        }
        $usersId = (int) ($input['users_id'] ?? 0);
        $user = new User();
        if ($usersId <= 0 || !$user->getFromDB($usersId)) {
            return self::fail(__('Select a person.', 'iam'));
        }
        // The person must belong to an entity the session can see (no assignment of people out of scope)
        if (!self::userVisible($usersId)) {
            return self::fail(__('The person does not exist or you are not allowed to see it.', 'iam'));
        }
        $data = self::cleanDates([
            'plugin_iam_positions_id' => (int) $position->getID(),
            'users_id'                => $usersId,
            'type'                    => (string) ($input['type'] ?? 'holder'),
            'is_primary'              => empty($input['is_primary']) ? 0 : 1,
            'date_begin'              => $input['date_begin'] ?? null,
            'date_end'                => $input['date_end'] ?? null,
            'tickets_id'              => (int) ($input['tickets_id'] ?? 0),
        ]);
        $errors = PositionPeriod::validate($data, self::otherRows($usersId, 0), date('Y-m-d'));
        if ($errors !== []) {
            return self::fail(self::errorMessage($errors[0]));
        }
        if (!self::ticketAllowed($data['tickets_id'])) {
            return self::fail(__('The ticket does not exist or you are not allowed to see it.', 'iam'));
        }
        // The entity is always the one of the position, never taken from the request
        $data['entities_id'] = (int) $position->fields['entities_id'];
        foreach ($data as $k => $v) {
            if ($v === null) {
                unset($data[$k]);
            }
        }
        return $data;
    }

    public function prepareInputForUpdate($input)
    {
        if (!is_array($input)) {
            return false;
        }
        // The position, the person and the entity never change: close the assignment and create a new one
        unset($input['plugin_iam_positions_id'], $input['users_id'], $input['entities_id']);
        $allowed = array_flip(['id', 'type', 'is_primary', 'date_begin', 'date_end', 'tickets_id']);
        $input = self::cleanDates(array_intersect_key($input, $allowed));
        $merged = array_merge($this->fields, $input);
        if (array_key_exists('is_primary', $input)) {
            $input['is_primary'] = empty($input['is_primary']) ? 0 : 1;
            $merged['is_primary'] = $input['is_primary'];
        }
        $errors = PositionPeriod::validate($merged, self::otherRows((int) $this->fields['users_id'], (int) $this->getID()), date('Y-m-d'));
        if ($errors !== []) {
            return self::fail(self::errorMessage($errors[0]));
        }
        if (isset($input['tickets_id'])) {
            $input['tickets_id'] = (int) $input['tickets_id'];
            if ($input['tickets_id'] !== (int) $this->fields['tickets_id'] && !self::ticketAllowed($input['tickets_id'])) {
                return self::fail(__('The ticket does not exist or you are not allowed to see it.', 'iam'));
            }
        }
        return $input;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || $item->isNewItem() || !self::canView()) {
            return '';
        }
        if ($item instanceof User) {
            $n = countElementsInTable(self::getTable(), ['users_id' => $item->getID()]
                + getEntitiesRestrictCriteria(self::getTable(), '', '', false));
            return self::createTabEntry(__('Positions (IAM)', 'iam'), $n, null, self::getIcon());
        }
        if ($item instanceof Position) {
            $n = countElementsInTable(self::getTable(), ['plugin_iam_positions_id' => $item->getID()]
                + getEntitiesRestrictCriteria(self::getTable(), '', '', false));
            return self::createTabEntry(__('Assignments', 'iam'), $n, null, self::getIcon());
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof User || $item instanceof Position) {
            self::showFor($item);
            return true;
        }
        return false;
    }

    private static function showFor(CommonDBTM $item): void
    {
        global $DB;
        $forUser = $item instanceof User;
        $today = date('Y-m-d');
        $rows = [];
        $iter = $DB->request([
            'FROM'  => self::getTable(),
            'WHERE' => [($forUser ? 'users_id' : 'plugin_iam_positions_id') => $item->getID()]
                + getEntitiesRestrictCriteria(self::getTable(), '', '', false),
            'ORDER' => ['date_end IS NULL DESC', 'date_begin DESC', 'id DESC'],
        ]);
        $labels = self::typeLabels();
        foreach ($iter as $r) {
            $position = new Position();
            $name = $position->getFromDB((int) $r['plugin_iam_positions_id']) ? (string) $position->fields['completename'] : '#' . $r['plugin_iam_positions_id'];
            $rows[] = [
                'id'        => $r['id'],
                'position'  => $name,
                'url'       => Position::canView() ? Position::getFormURLWithID((int) $r['plugin_iam_positions_id']) : '',
                'person'    => $forUser ? '' : User::getFriendlyNameById((int) $r['users_id']),
                'type'      => $labels[$r['type']] ?? $r['type'],
                'primary'   => (int) $r['is_primary'] === 1,
                'begin'     => (string) $r['date_begin'],
                'end'       => (string) $r['date_end'],
                'active'    => PositionPeriod::isActive($r['date_begin'], $r['date_end'], $today),
                'ticket'    => (int) $r['tickets_id'] > 0 ? (int) $r['tickets_id'] : 0,
            ];
        }
        $canAdd = self::canCreate();
        TemplateRenderer::getInstance()->display('@iam/positions_tab.html.twig', [
            'rows'     => $rows,
            'for_user' => $forUser,
            'can_add'  => $canAdd,
            'can_edit' => self::canUpdate(),
            'types'    => $labels,
            'item_id'  => $item->getID(),
            'action'   => plugin_iam_url('front/position_user.form.php'),
        ]);
    }
}
