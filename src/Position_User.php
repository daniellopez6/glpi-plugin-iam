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
use Glpi\DBAL\QuerySubQuery;
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
    public bool $dohistory = true;

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

    /** Recursion-aware visibility of a position (own entity, or a recursive position of an ancestor entity). */
    private static function positionVisible(int $positionId): bool
    {
        $position = new Position();
        return $position->getFromDB($positionId)
            && Session::haveAccessToEntity((int) $position->fields['entities_id'], (int) $position->fields['is_recursive'] === 1);
    }

    /** An assignment is visible when its position and its person are. */
    private static function rowVisible(int $positionId, int $usersId): bool
    {
        return self::positionVisible($positionId) && self::userVisible($usersId);
    }

    /**
     * Search restriction implementing canViewItem() in SQL (used for the notes of assignments): READ, position visible
     * in the active entities (recursion-aware) and person visible (an authorization of the person in an active
     * entity, or a recursive one in an ancestor entity: the same as userVisible()).
     *
     * @return array<mixed>
     */
    public static function visibilityCriteria(): array
    {
        $t = self::getTable();
        if (!self::canView()) {
            return ["$t.id" => 0];
        }
        $pt = Position::getTable();
        $put = Profile_User::getTable();
        return [
            "$t.plugin_iam_positions_id" => new QuerySubQuery([
                'SELECT' => "$pt.id",
                'FROM'   => $pt,
                'WHERE'  => getEntitiesRestrictCriteria($pt, '', '', true),
            ]),
            "$t.users_id" => new QuerySubQuery([
                'SELECT' => "$put.users_id",
                'FROM'   => $put,
                'WHERE'  => getEntitiesRestrictCriteria($put, '', '', true),
            ]),
        ];
    }

    public function canViewItem(): bool
    {
        return self::canView() && self::rowVisible((int) ($this->fields['plugin_iam_positions_id'] ?? 0), (int) ($this->fields['users_id'] ?? 0));
    }

    public function canCreateItem(): bool
    {
        return self::canCreate()
            && self::rowVisible((int) ($this->input['plugin_iam_positions_id'] ?? 0), (int) ($this->input['users_id'] ?? 0));
    }

    public function canUpdateItem(): bool
    {
        return self::canUpdate() && self::rowVisible((int) ($this->fields['plugin_iam_positions_id'] ?? 0), (int) ($this->fields['users_id'] ?? 0));
    }

    public function canDeleteItem(): bool
    {
        return false;
    }

    public function canPurgeItem(): bool
    {
        return false;
    }

    public function defineTabs($options = [])
    {
        $tabs = [];
        $this->addDefaultFormTab($tabs);
        $this->addStandardTab(Note::class, $tabs, $options);
        $this->addStandardTab(\Log::class, $tabs, $options);
        return $tabs;
    }

    /**
     * Read-only summary of an assignment (it is edited from the person or position tab); its page carries the
     * "Log (IAM)" tab.
     */
    public function showForm($ID, array $options = [])
    {
        if (!$this->getFromDB((int) $ID) || !$this->canViewItem()) {
            return false;
        }
        $position = new Position();
        $positionId = (int) $this->fields['plugin_iam_positions_id'];
        $ticket = (int) $this->fields['tickets_id'];
        TemplateRenderer::getInstance()->display('@iam/position_user_form.html.twig', [
            'help'         => Help::context(),
            'position'     => $position->getFromDB($positionId) ? (string) $position->fields['completename'] : '#' . $positionId,
            'position_url' => Position::canView() ? Position::getFormURLWithID($positionId) : '',
            'person'       => (string) User::getFriendlyNameById((int) $this->fields['users_id']),
            'type'         => self::typeLabels()[(string) $this->fields['type']] ?? (string) $this->fields['type'],
            'primary'      => (int) $this->fields['is_primary'] === 1,
            'begin'        => (string) $this->fields['date_begin'],
            'end'          => (string) $this->fields['date_end'],
            'active'       => PositionPeriod::isActive($this->fields['date_begin'], $this->fields['date_end'], date('Y-m-d')),
            'ticket'       => $ticket > 0 && self::ticketAllowed($ticket) ? $ticket : 0,
        ]);
        return true;
    }

    /** User-facing message of an assignment error code, prefixed with the code. */
    public static function errorMessage(string $code): string
    {
        return ErrorMessage::format($code, match ($code) {
            'date_order'            => __('The end date cannot be before the begin date.', 'iam'),
            'date_invalid'          => __('A date is not valid (expected format YYYY-MM-DD).', 'iam'),
            'primary_duplicate'     => __('The person already has an active primary position.', 'iam'),
            'type_invalid'          => __('The assignment type is not valid.', 'iam'),
            'agent_requires_ticket' => __('The agent can only assign a position with its ticket.', 'iam'),
            'position_required'     => __('Select a position.', 'iam'),
            'position_inactive'     => __('The position is not active.', 'iam'),
            'person_required'       => __('Select a person.', 'iam'),
            'person_invalid'        => __('The person does not exist or you are not allowed to see it.', 'iam'),
            'ticket_invalid'        => __('The ticket does not exist or you are not allowed to see it.', 'iam'),
            default                 => __('The assignment is not valid.', 'iam'),
        });
    }

    /** @param list<string> $codes */
    private static function failCodes(array $codes): false
    {
        return self::fail(ErrorMessage::combine(array_map(self::errorMessage(...), $codes)));
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

    public static function userVisible(int $usersId): bool
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
            return self::failCodes(['position_required']);
        }
        if ((int) $position->fields['is_active'] !== 1) {
            return self::failCodes(['position_inactive']);
        }
        $usersId = (int) ($input['users_id'] ?? 0);
        $user = new User();
        if ($usersId <= 0 || !$user->getFromDB($usersId)) {
            return self::failCodes(['person_required']);
        }
        // The person must belong to an entity the session can see (no assignment of people out of scope)
        if (!self::userVisible($usersId)) {
            return self::failCodes(['person_invalid']);
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
        $errors = array_merge(
            PositionPeriod::validate($data, self::otherRows($usersId, 0), date('Y-m-d')),
            PositionPeriod::agentErrors($data, Rights::activeRoleKey())
        );
        if ($errors !== []) {
            return self::failCodes($errors);
        }
        if (!self::ticketAllowed($data['tickets_id'])) {
            return self::failCodes(['ticket_invalid']);
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
        // Only the end date and the ticket can change; position, person, entity, type, primary flag and begin
        // date are corrected by closing the assignment and creating a new one
        $input = self::cleanDates(PositionPeriod::filterUpdate($input));
        $merged = array_merge($this->fields, $input);
        $errors = PositionPeriod::validate($merged, self::otherRows((int) $this->fields['users_id'], (int) $this->getID()), date('Y-m-d'));
        if ($errors !== []) {
            return self::failCodes($errors);
        }
        if (isset($input['tickets_id'])) {
            $input['tickets_id'] = (int) $input['tickets_id'];
            if ($input['tickets_id'] !== (int) $this->fields['tickets_id'] && !self::ticketAllowed($input['tickets_id'])) {
                return self::failCodes(['ticket_invalid']);
            }
        }
        return $input;
    }

    /**
     * Assignments of a person or of a position that the session may see (position and person visible).
     *
     * @return list<array<string,mixed>>
     */
    private static function visibleRows(CommonDBTM $item): array
    {
        global $DB;
        $forUser = $item instanceof User;
        if ($forUser ? !self::userVisible((int) $item->getID()) : !self::positionVisible((int) $item->getID())) {
            return [];
        }
        $pt = Position::getTable();
        $t = self::getTable();
        $iter = $DB->request([
            'SELECT'     => ["$t.*"],
            'FROM'       => $t,
            'INNER JOIN' => [$pt => ['ON' => [$t => 'plugin_iam_positions_id', $pt => 'id']]],
            'WHERE'      => ["$t." . ($forUser ? 'users_id' : 'plugin_iam_positions_id') => $item->getID()]
                + getEntitiesRestrictCriteria($pt, '', '', true),
            'ORDER'      => ["$t.date_end IS NULL DESC", "$t.date_begin DESC", "$t.id DESC"],
        ]);
        $rows = [];
        $seen = [];
        foreach ($iter as $r) {
            $uid = (int) $r['users_id'];
            $seen[$uid] ??= self::userVisible($uid);
            if ($seen[$uid]) {
                $rows[] = $r;
            }
        }
        return $rows;
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || $item->isNewItem() || !self::canView()) {
            return '';
        }
        if ($item instanceof User) {
            return self::createTabEntry(__('Positions (IAM)', 'iam'), count(self::visibleRows($item)), null, self::getIcon());
        }
        if ($item instanceof Position) {
            return self::createTabEntry(__('Assignments', 'iam'), count(self::visibleRows($item)), null, self::getIcon());
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        // The tab loader calls this directly from the tab id: the right is checked here too
        if (!self::canView()) {
            return false;
        }
        if ($item instanceof User || $item instanceof Position) {
            self::showFor($item);
            return true;
        }
        return false;
    }

    private static function showFor(CommonDBTM $item): void
    {
        $forUser = $item instanceof User;
        $today = date('Y-m-d');
        $rows = [];
        $labels = self::typeLabels();
        foreach (self::visibleRows($item) as $r) {
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
                'page'      => self::getFormURLWithID((int) $r['id']),
            ];
        }
        $canAdd = self::canCreate();
        TemplateRenderer::getInstance()->display('@iam/positions_tab.html.twig', [
            'help'     => Help::context(),
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
