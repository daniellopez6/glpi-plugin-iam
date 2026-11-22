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
use Entity;
use Glpi\Application\View\TemplateRenderer;
use Glpi\DBAL\QuerySubQuery;
use Plugin;
use Session;
use Ticket;
use User;

/**
 * Access register: an access that was actually granted to a person on a role of a resource (spec §7, "registration
 * model": the request and its approval live in the GLPI ticket; the grant records what was given).
 *
 * Nothing is ever deleted: a revocation is a status change. The entity of a grant is the entity of its resource.
 *
 * Rights (plugin_iam):
 * - view:   READ (every grant of a resource visible in the active entities) or READ_OWNED (grants of resources the
 *           session owns, as person or current group member);
 * - create: CREATE, on a resource the session can see (Resource::canViewItem), never for oneself;
 * - update: UPDATE (full correction, with history) or UPDATE_OWNED on owned resources, limited to requesting a
 *           revocation/modification with a justification; never on one's own grant;
 * - delete/purge: never (not even with a crafted profile that carries DELETE/PURGE bits).
 */
class Grant extends CommonDBTM
{
    public static string $rightname = Rights::ACCESS;
    public bool $dohistory = true;

    /** Accounts Inventory item class: only ever resolved from this constant, never from the input. */
    private const ACCOUNT_CLASS = 'GlpiPlugin\\Accounts\\Account';

    public static function getTypeName($nb = 0)
    {
        return _n('Grant', 'Grants', $nb, 'iam');
    }

    public static function getIcon()
    {
        return 'ti ti-lock-access';
    }

    public static function getMenuName()
    {
        return __('Grants', 'iam');
    }

    /** @return array<string,string> */
    public static function statusLabels(): array
    {
        return [
            'pending'        => __('Pending', 'iam'),
            'active'         => __('Active', 'iam'),
            'revoke_pending' => __('Revocation pending', 'iam'),
            'modify_pending' => __('Modification pending', 'iam'),
            'revoked'        => __('Revoked', 'iam'),
            'expired'        => __('Expired', 'iam'),
        ];
    }

    /** @return array<string,string> */
    public static function mfaLabels(): array
    {
        return [
            'yes' => __('Yes', 'iam'),
            'no'  => __('No', 'iam'),
            'na'  => __('Not applicable', 'iam'),
        ];
    }

    /** @return array<string,string> */
    public static function sourceLabels(): array
    {
        return [
            'manual' => __('Manual', 'iam'),
            'api'    => __('API', 'iam'),
            'agent'  => __('Agent', 'iam'),
        ];
    }

    /**
     * Visibility follows the resource, not the grant's own entity column: a grant on a recursive resource of a parent
     * entity is visible from the child entities. GLPI's generic entity filter (search, API lists) would only compare
     * the grant's entities_id, so it is disabled here and replaced by visibilityCriteria() (addDefaultWhere hook)
     * and canViewItem(), which implement the same predicate.
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
        return (bool) Session::haveRightsOr(self::$rightname, [READ, READ_OWNED]);
    }

    public static function canCreate(): bool
    {
        return (bool) Session::haveRight(self::$rightname, CREATE);
    }

    public static function canUpdate(): bool
    {
        return (bool) Session::haveRightsOr(self::$rightname, [UPDATE, UPDATE_OWNED]);
    }

    public static function canDelete(): bool
    {
        return false;
    }

    public static function canPurge(): bool
    {
        return false;
    }

    // Item rights

    private static function sessionUser(): int
    {
        return (int) Session::getLoginUserID();
    }

    private static function fullEditor(): bool
    {
        return (bool) Session::haveRight(self::$rightname, UPDATE);
    }

    private static function canApprove(): bool
    {
        return (bool) Session::haveRight(Rights::APPROVE, UPDATE);
    }

    /** @return array<string,mixed>|null the resource row, or null when it does not exist */
    private static function resourceRow(int $id): ?array
    {
        $resource = new Resource();
        return $id > 0 && $resource->getFromDB($id) ? $resource->fields : null;
    }

    /** @param array<string,mixed> $resource */
    private static function entityVisible(array $resource): bool
    {
        return Session::haveAccessToEntity((int) $resource['entities_id'], (int) ($resource['is_recursive'] ?? 0) === 1);
    }

    /** @param array<string,mixed> $resource */
    private static function owns(array $resource): bool
    {
        return Ownership::isOwner($resource, self::sessionUser(), Rights::currentGroupIds());
    }

    /**
     * The view predicate (same as visibilityCriteria()): resource visible in the active entities (recursion-aware)
     * and either READ, or READ_OWNED and the session owns the resource.
     *
     * @param array<string,mixed> $resource
     */
    private static function seesResource(array $resource): bool
    {
        if (!self::entityVisible($resource)) {
            return false;
        }
        if (Rights::canReadAll()) {
            return true;
        }
        return (bool) Session::haveRight(self::$rightname, READ_OWNED) && self::owns($resource);
    }

    /**
     * Search/API restriction implementing the view predicate in SQL: the grant's resource is visible in the active
     * entities (recursion-aware: recursive resources of an ancestor entity count) and, for a session without READ,
     * the resource is owned by the session user or one of the session groups (READ_OWNED). A session with neither
     * right sees nothing.
     *
     * @return array<mixed>
     */
    public static function visibilityCriteria(): array
    {
        $t = self::getTable();
        $rt = Resource::getTable();
        if (!Rights::canReadAll() && !Session::haveRight(self::$rightname, READ_OWNED)) {
            return ["$t.id" => 0];
        }
        $where = getEntitiesRestrictCriteria($rt, '', '', true);
        if (!Rights::canReadAll()) {
            $where[] = Ownership::resourceCriteria(self::sessionUser(), Rights::currentGroupIds(), $rt);
        }
        return ["$t.plugin_iam_resources_id" => new QuerySubQuery(['SELECT' => "$rt.id", 'FROM' => $rt, 'WHERE' => $where])];
    }

    public function canViewItem(): bool
    {
        if (!self::canView()) {
            return false;
        }
        $resource = self::resourceRow((int) ($this->fields['plugin_iam_resources_id'] ?? 0));
        return $resource !== null && self::seesResource($resource);
    }

    public function canCreateItem(): bool
    {
        if (!self::canCreate()) {
            return false;
        }
        $usersId = (int) ($this->input['users_id'] ?? 0);
        if ($usersId <= 0 || $usersId === self::sessionUser()) {
            return false;
        }
        $role = new Role();
        $resource = new Resource();
        return $role->getFromDB((int) ($this->input['plugin_iam_roles_id'] ?? 0))
            && $resource->getFromDB((int) $role->fields['plugin_iam_resources_id'])
            && !$resource->isDeleted()
            && $resource->canViewItem();
    }

    public function canUpdateItem(): bool
    {
        if (!self::canUpdate() || !$this->canViewItem()) {
            return false;
        }
        // Nobody edits their own access
        if ((int) ($this->fields['users_id'] ?? 0) === self::sessionUser()) {
            return false;
        }
        if (self::fullEditor()) {
            return true;
        }
        $resource = self::resourceRow((int) ($this->fields['plugin_iam_resources_id'] ?? 0));
        return $resource !== null && (bool) Session::haveRight(self::$rightname, UPDATE_OWNED) && self::owns($resource);
    }

    public function canDeleteItem(): bool
    {
        return false;
    }

    public function canPurgeItem(): bool
    {
        return false;
    }

    public function delete(array $input, $force = false, $history = true)
    {
        // A revocation is a status change: the register keeps every grant
        return false;
    }

    // Input validation

    /** User-facing message of an error code (GrantRules or reference checks). */
    public static function errorMessage(string $code): string
    {
        return match ($code) {
            'date_invalid'                         => __('A date is not valid (expected format YYYY-MM-DD).', 'iam'),
            'date_order'                           => __('The end date cannot be before the begin date.', 'iam'),
            'status_invalid'                       => __('The status is not valid.', 'iam'),
            'status_transition_invalid'            => __('This status change is not allowed.', 'iam'),
            'mfa_invalid'                          => __('The MFA value is not valid.', 'iam'),
            'agent_cannot_activate_without_ticket' => __('The agent can only register a grant with its ticket.', 'iam'),
            'agent_cannot_approve'                 => __('The agent cannot approve or revoke grants.', 'iam'),
            'revoke_requires_reason'               => __('A revocation needs a reason.', 'iam'),
            'self_service'                         => __('Nobody can register or change their own access.', 'iam'),
            'approver_is_beneficiary'              => __('The approver cannot be the person who receives the access.', 'iam'),
            'security_approver_conflict'           => __('The security approver cannot be the person who receives the access nor who registered it.', 'iam'),
            'security_approver_right'              => __('Only a security approver can set the security approval.', 'iam'),
            'owner_field_forbidden'                => __('As owner you can only request a revocation or a modification, with its justification.', 'iam'),
            'owner_status_forbidden'               => __('As owner you can only request a revocation or a modification.', 'iam'),
            'ticket_invalid'                       => __('The ticket does not exist or you are not allowed to see it.', 'iam'),
            'approver_invalid'                     => __('The approver does not exist or you are not allowed to see it.', 'iam'),
            'approver_is_recorder'                 => __('The approver cannot be the person who registers the access.', 'iam'),
            'approver_security_not_self'           => __('The security approval is always recorded in the name of the approver who gives it.', 'iam'),
            'owner_request_required'               => __('As owner you can only request a revocation or a modification, with its justification.', 'iam'),
            'owner_justification_required'         => __('A revocation or modification request needs a justification.', 'iam'),
            'account_invalid'                      => __('The account does not exist or you are not allowed to see it.', 'iam'),
            default                                => __('The grant is not valid.', 'iam'),
        };
    }

    /** @param list<string> $codes */
    private static function failAll(array $codes): false
    {
        foreach (array_unique($codes) as $code) {
            Session::addMessageAfterRedirect(self::errorMessage($code), false, ERROR);
        }
        return false;
    }

    private static function fail(string $message): false
    {
        Session::addMessageAfterRedirect($message, false, ERROR);
        return false;
    }

    /** API or form (the CLI has no HTTP request). */
    private static function viaApi(): bool
    {
        return !isCommandLine() && isAPI();
    }

    private static function ticketAllowed(int $ticketId): bool
    {
        $ticket = new Ticket();
        return $ticket->getFromDB($ticketId) && $ticket->canViewItem();
    }

    private static function userExists(int $usersId): bool
    {
        $user = new User();
        return $user->getFromDB($usersId) && (int) $user->fields['is_deleted'] === 0;
    }

    /** Accounts Inventory is integrated only when the plugin is active and its class exists. */
    public static function accountsAvailable(): bool
    {
        return Plugin::isPluginActive('accounts') && class_exists(self::ACCOUNT_CLASS);
    }

    private static function accountAllowed(int $accountId): bool
    {
        if (!self::accountsAvailable()) {
            return false;
        }
        $account = getItemForItemtype(self::ACCOUNT_CLASS);
        return $account instanceof CommonDBTM
            && $account->getFromDB($accountId)
            && !$account->isDeleted()
            && $account->canViewItem();
    }

    /**
     * Existence and visibility of the referenced items that are set or changed.
     *
     * @param array<string,mixed> $values
     *
     * @return list<string>
     */
    private static function referenceErrors(array $values): array
    {
        $errors = [];
        if (array_key_exists('tickets_id', $values) && (int) $values['tickets_id'] > 0 && !self::ticketAllowed((int) $values['tickets_id'])) {
            $errors[] = 'ticket_invalid';
        }
        foreach (['users_id_approver', 'users_id_approver_security'] as $field) {
            // Same error for a missing person and for one outside the visible entities (no existence oracle)
            $uid = (int) ($values[$field] ?? 0);
            if (array_key_exists($field, $values) && $uid > 0 && (!self::userExists($uid) || !Position_User::userVisible($uid))) {
                $errors[] = 'approver_invalid';
            }
        }
        if (
            array_key_exists('plugin_accounts_accounts_id', $values)
            && (int) $values['plugin_accounts_accounts_id'] > 0
            && !self::accountAllowed((int) $values['plugin_accounts_accounts_id'])
        ) {
            $errors[] = 'account_invalid';
        }
        return $errors;
    }

    /**
     * Whitelisted input with typed foreign keys and blank dates as null.
     *
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    private static function sanitize(array $input, bool $isUpdate): array
    {
        // GLPI internal keys (_no_history...) are dropped as well: the history of the register is not optional
        $data = InputGuard::filter($input, FieldSets::GRANT, FieldSets::GRANT_IMMUTABLE, $isUpdate);
        foreach ($data as $key => $value) {
            if (str_ends_with($key, '_id') || str_contains($key, '_id_')) {
                $data[$key] = (int) $value;
            } elseif ($key === 'date_begin' || $key === 'date_end') {
                $v = is_scalar($value) ? trim((string) $value) : '';
                $data[$key] = $v === '' ? null : $v;
            } else {
                $data[$key] = is_scalar($value) ? (string) $value : '';
            }
        }
        return $data;
    }

    public function prepareInputForAdd($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $data = self::sanitize($input, false);
        $role = new Role();
        if (!$role->getFromDB((int) ($data['plugin_iam_roles_id'] ?? 0))) {
            return self::fail(__('Select a role.', 'iam'));
        }
        $resource = new Resource();
        if (!$resource->getFromDB((int) $role->fields['plugin_iam_resources_id']) || $resource->isDeleted()) {
            return self::fail(__('The role does not exist or its resource is in the trash.', 'iam'));
        }
        if ((int) ($data['plugin_iam_resources_id'] ?? 0) > 0 && (int) $data['plugin_iam_resources_id'] !== (int) $resource->getID()) {
            return self::fail(__('The role does not belong to the selected resource.', 'iam'));
        }
        if (!$resource->canViewItem()) {
            return self::fail(__('The resource does not exist or you are not allowed to see it.', 'iam'));
        }
        $usersId = (int) ($data['users_id'] ?? 0);
        if ($usersId <= 0 || !self::userExists($usersId) || !Position_User::userVisible($usersId)) {
            return self::fail(__('The person does not exist or you are not allowed to see it.', 'iam'));
        }

        // Taken from the server, never from the request
        $roleKey = Rights::activeRoleKey();
        $data['plugin_iam_resources_id'] = (int) $resource->getID();
        $data['entities_id'] = (int) $resource->fields['entities_id'];
        $data['users_id_recorder'] = self::sessionUser();
        $data['source'] = GrantRules::source(self::viaApi(), $roleKey);
        $data['status'] = ($data['status'] ?? '') === '' ? 'active' : $data['status'];
        $data['mfa'] = ($data['mfa'] ?? '') === '' ? 'na' : $data['mfa'];
        $data['date_begin'] ??= date('Y-m-d');
        unset($data['revoke_reason']);
        if ((int) ($data['users_id_approver_security'] ?? 0) === 0) {
            unset($data['users_id_approver_security']);
        }

        $errors = array_merge(
            GrantRules::separation($data, self::sessionUser()),
            GrantRules::approvalErrors($data, self::canApprove(), self::sessionUser()),
            GrantRules::validate($data, false, $roleKey),
            self::referenceErrors($data)
        );
        if ($errors !== []) {
            return self::failAll($errors);
        }
        return array_filter($data, static fn ($v): bool => $v !== null);
    }

    public function prepareInputForUpdate($input)
    {
        if (!is_array($input)) {
            return false;
        }
        $clean = self::sanitize($input, true);
        $changes = GrantRules::changes($clean, $this->fields);
        $id = ['id' => (int) $this->getID()];
        if ($changes === []) {
            return $id;
        }
        $merged = array_merge($this->fields, $changes);
        $errors = GrantRules::separation($merged, self::sessionUser());
        if (!self::fullEditor()) {
            // The request must carry its own justification (the stored one belongs to the registration)
            $justification = (string) ($clean['justification'] ?? '');
            $errors = array_merge($errors, GrantRules::ownerErrors($changes, (string) $this->fields['status'], $justification));
        }
        $errors = array_merge(
            $errors,
            GrantRules::approvalErrors($changes, self::canApprove(), self::sessionUser()),
            GrantRules::validate($changes, true, Rights::activeRoleKey(), $this->fields),
            self::referenceErrors($changes)
        );
        if ($errors !== []) {
            return self::failAll($errors);
        }
        // The revocation date is the server's
        if (($changes['status'] ?? '') === 'revoked') {
            $changes['date_revoked'] = $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s');
        }
        return $changes + $id;
    }

    // Search

    public function rawSearchOptions()
    {
        $t = self::getTable();
        $tab = [['id' => 'common', 'name' => self::getTypeName(2)]];
        $tab[] = ['id' => 2, 'table' => $t, 'field' => 'id', 'name' => __('ID'), 'datatype' => 'itemlink', 'massiveaction' => false];
        $tab[] = ['id' => 3, 'table' => 'glpi_users', 'field' => 'name', 'linkfield' => 'users_id', 'name' => __('Person', 'iam'),
            'datatype' => 'dropdown', 'right' => 'all', 'massiveaction' => false];
        $tab[] = ['id' => 4, 'table' => Resource::getTable(), 'field' => 'name', 'linkfield' => 'plugin_iam_resources_id',
            'name' => Resource::getTypeName(1), 'datatype' => 'dropdown', 'massiveaction' => false];
        $tab[] = ['id' => 5, 'table' => Role::getTable(), 'field' => 'name', 'linkfield' => 'plugin_iam_roles_id',
            'name' => Role::getTypeName(1), 'datatype' => 'dropdown', 'massiveaction' => false];
        $tab[] = ['id' => 6, 'table' => Role::getTable(), 'field' => 'level', 'linkfield' => 'plugin_iam_roles_id',
            'name' => __('Level', 'iam'), 'datatype' => 'specific', 'searchtype' => ['equals', 'notequals'], 'searchequalsonfield' => true,
            'massiveaction' => false];
        $tab[] = ['id' => 7, 'table' => $t, 'field' => 'status', 'name' => __('Status', 'iam'), 'datatype' => 'specific',
            'searchtype' => ['equals', 'notequals'], 'massiveaction' => false];
        $tab[] = ['id' => 8, 'table' => $t, 'field' => 'date_begin', 'name' => __('Begin date', 'iam'), 'datatype' => 'date', 'massiveaction' => false];
        $tab[] = ['id' => 9, 'table' => $t, 'field' => 'date_end', 'name' => __('End date', 'iam'), 'datatype' => 'date', 'massiveaction' => false];
        // The ticket by number only: joining glpi_tickets would show ticket titles to profiles without ticket rights
        $tab[] = ['id' => 10, 'table' => $t, 'field' => 'tickets_id', 'name' => __('Ticket', 'iam'), 'datatype' => 'number', 'massiveaction' => false];
        $tab[] = ['id' => 11, 'table' => $t, 'field' => 'source', 'name' => __('Source', 'iam'), 'datatype' => 'specific',
            'searchtype' => ['equals', 'notequals'], 'massiveaction' => false];
        $tab[] = ['id' => 12, 'table' => 'glpi_users', 'field' => 'name', 'linkfield' => 'users_id_approver', 'name' => __('Approver', 'iam'),
            'datatype' => 'dropdown', 'right' => 'all', 'massiveaction' => false];
        $tab[] = ['id' => 13, 'table' => 'glpi_users', 'field' => 'name', 'linkfield' => 'users_id_approver_security',
            'name' => __('Security approver', 'iam'), 'datatype' => 'dropdown', 'right' => 'all', 'massiveaction' => false];
        $tab[] = ['id' => 14, 'table' => $t, 'field' => 'mfa', 'name' => __('MFA', 'iam'), 'datatype' => 'specific',
            'searchtype' => ['equals', 'notequals'], 'massiveaction' => false];
        $tab[] = ['id' => 15, 'table' => 'glpi_users', 'field' => 'name', 'linkfield' => 'users_id_recorder', 'name' => __('Recorded by', 'iam'),
            'datatype' => 'dropdown', 'right' => 'all', 'massiveaction' => false];
        $tab[] = ['id' => 16, 'table' => $t, 'field' => 'date_revoked', 'name' => __('Revocation date', 'iam'), 'datatype' => 'datetime',
            'massiveaction' => false];
        // Text fields have options so that their changes are kept in the history
        $tab[] = ['id' => 20, 'table' => $t, 'field' => 'justification', 'name' => __('Justification', 'iam'), 'datatype' => 'text',
            'massiveaction' => false];
        $tab[] = ['id' => 22, 'table' => $t, 'field' => 'revoke_reason', 'name' => __('Revocation reason', 'iam'), 'datatype' => 'text',
            'massiveaction' => false];
        // Account names only for sessions that may read Accounts Inventory (they are the only ones able to change it)
        if (self::accountsAvailable() && Session::haveRight('plugin_accounts', READ)) {
            $tab[] = ['id' => 23, 'table' => 'glpi_plugin_accounts_accounts', 'field' => 'name', 'linkfield' => 'plugin_accounts_accounts_id',
                'name' => __('Account', 'iam'), 'datatype' => 'itemlink', 'massiveaction' => false];
        }
        $tab[] = ['id' => 19, 'table' => $t, 'field' => 'date_mod', 'name' => __('Last update'), 'datatype' => 'datetime', 'massiveaction' => false];
        $tab[] = ['id' => 121, 'table' => $t, 'field' => 'date_creation', 'name' => __('Creation date'), 'datatype' => 'datetime',
            'massiveaction' => false];
        $tab[] = ['id' => 80, 'table' => 'glpi_entities', 'field' => 'completename', 'name' => Entity::getTypeName(1), 'datatype' => 'dropdown',
            'massiveaction' => false];
        return $tab;
    }

    public static function getSpecificValueToDisplay($field, $values, array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        $v = (string) ($values[$field] ?? '');
        return match ($field) {
            'status' => htmlescape(self::statusLabels()[$v] ?? $v),
            'source' => htmlescape(self::sourceLabels()[$v] ?? $v),
            'mfa'    => htmlescape(self::mfaLabels()[$v] ?? $v),
            default  => parent::getSpecificValueToDisplay($field, $values, $options),
        };
    }

    public static function getSpecificValueToSelect($field, $name = '', $values = '', array $options = [])
    {
        if (!is_array($values)) {
            $values = [$field => $values];
        }
        $map = ['status' => self::statusLabels(), 'source' => self::sourceLabels(), 'mfa' => self::mfaLabels()];
        if (isset($map[$field])) {
            return Dropdown::showFromArray($name, $map[$field], ['display' => false, 'value' => $values[$field] ?? '']);
        }
        return parent::getSpecificValueToSelect($field, $name, $values, $options);
    }

    public function defineTabs($options = [])
    {
        $tabs = [];
        $this->addDefaultFormTab($tabs);
        $this->addStandardTab(\Log::class, $tabs, $options);
        return $tabs;
    }

    // Form

    /**
     * Statuses offered in the form: the current one and its allowed transitions (owners: requests only).
     *
     * @return array<string,string>
     */
    private function statusChoices(string $mode): array
    {
        $labels = self::statusLabels();
        if ($mode === 'new') {
            return array_intersect_key($labels, array_flip(GrantRules::TRANSITIONS['']));
        }
        $current = (string) $this->fields['status'];
        $next = GrantRules::TRANSITIONS[$current] ?? [];
        if ($mode === 'owner') {
            // Only the requests: the form always files a status change
            return array_intersect_key($labels, array_flip(array_intersect($next, GrantRules::OWNER_STATUSES)));
        } elseif ($mode !== 'full') {
            $next = [];
        }
        return array_intersect_key($labels, array_flip(array_merge([$current], $next)));
    }

    /**
     * Choices of the security approval for an approver: keep the current one, approve in one's own name, or clear it.
     *
     * @return array<int,string>
     */
    private function securityChoices(): array
    {
        $current = (int) ($this->fields['users_id_approver_security'] ?? 0);
        $me = self::sessionUser();
        $choices = [0 => __('Not approved', 'iam')];
        if ($current > 0 && $current !== $me) {
            $choices[$current] = (string) User::getFriendlyNameById($current);
        }
        $choices[$me] = __('Approved by me', 'iam');
        return $choices;
    }

    /** @return array{id:int,name:string,url:string,entity:int}|null */
    private static function resourceInfo(int $id): ?array
    {
        $resource = new Resource();
        if (!$resource->getFromDB($id) || !$resource->canViewItem()) {
            return null;
        }
        return ['id' => $id, 'name' => (string) $resource->fields['name'], 'url' => Resource::getFormURLWithID($id),
            'entity' => (int) $resource->fields['entities_id']];
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        $isNew = $this->isNewItem();
        if ($isNew) {
            $mode = 'new';
        } elseif ($this->canUpdateItem()) {
            $mode = self::fullEditor() ? 'full' : 'owner';
            // An owner only files requests: without a possible request transition the grant is read-only for them
            $requests = array_intersect(GrantRules::TRANSITIONS[(string) $this->fields['status']] ?? [], GrantRules::OWNER_STATUSES);
            if ($mode === 'owner' && $requests === []) {
                $mode = 'read';
            }
        } else {
            $mode = 'read';
        }

        // Presets of a new grant (from the User, Ticket or Resource tab) are used only when visible to the session
        $resourceId = $isNew ? (int) ($options['plugin_iam_resources_id'] ?? 0) : (int) $this->fields['plugin_iam_resources_id'];
        $resource = $resourceId > 0 ? self::resourceInfo($resourceId) : null;
        if ($isNew && $resource !== null) {
            $r = new Resource();
            if ($r->getFromDB($resourceId) && $r->isDeleted()) {
                $resource = null;
            }
        }
        $presetUser = (int) ($options['users_id'] ?? 0);
        if ($presetUser > 0 && (!self::userExists($presetUser) || !Position_User::userVisible($presetUser))) {
            $presetUser = 0;
        }
        $ticketId = $isNew ? (int) ($options['tickets_id'] ?? 0) : (int) $this->fields['tickets_id'];
        $ticketVisible = $ticketId > 0 && self::ticketAllowed($ticketId);
        if ($isNew && !$ticketVisible) {
            $ticketId = 0;
        }
        $accountId = (int) ($this->fields['plugin_accounts_accounts_id'] ?? 0);

        $role = new Role();
        $roleInfo = null;
        if (!$isNew && $role->getFromDB((int) $this->fields['plugin_iam_roles_id'])) {
            $roleInfo = ['name' => (string) $role->fields['name'], 'level' => Role::levelLabels()[$role->fields['level']] ?? (string) $role->fields['level']];
        }
        $userName = static fn (int $id): string => $id > 0 ? (string) User::getFriendlyNameById($id) : '';

        TemplateRenderer::getInstance()->display('@iam/grant_form.html.twig', [
            'item'            => $this,
            'params'          => $options,
            'mode'            => $mode,
            'pick_resource'   => $isNew && $resource === null,
            'resource'        => $resource,
            'role'            => $roleInfo,
            'preset_user'     => $presetUser,
            'beneficiary'     => $isNew ? '' : $userName((int) $this->fields['users_id']),
            'approver'        => $isNew ? '' : $userName((int) $this->fields['users_id_approver']),
            'security'        => $isNew ? '' : $userName((int) $this->fields['users_id_approver_security']),
            'recorder'        => $isNew ? '' : $userName((int) $this->fields['users_id_recorder']),
            'entity'          => $isNew ? '' : Dropdown::getDropdownName(Entity::getTable(), (int) $this->fields['entities_id']),
            'source'          => self::sourceLabels()[(string) ($this->fields['source'] ?? '')] ?? '',
            'ticket_id'       => $ticketId,
            'ticket_visible'  => $ticketId === 0 || $ticketVisible,
            'can_approve'     => self::canApprove(),
            'security_choices' => $this->securityChoices(),
            'accounts'        => self::accountsAvailable(),
            'account_id'      => $accountId,
            'account_visible' => $accountId === 0 || self::accountAllowed($accountId),
            'statuses'        => $this->statusChoices($mode),
            'mfa_labels'      => self::mfaLabels(),
            'status_label'    => self::statusLabels()[(string) ($this->fields['status'] ?? '')] ?? '',
            'mfa_label'       => self::mfaLabels()[(string) ($this->fields['mfa'] ?? '')] ?? '',
            'action'          => self::getFormURL(),
        ]);
        return true;
    }

    // Tabs on User, Ticket and Resource

    /**
     * Grants of a person, a ticket or a resource that the session may see.
     *
     * @return list<array<string,mixed>>
     */
    private static function visibleRows(CommonDBTM $item): array
    {
        global $DB;
        $t = self::getTable();
        $field = match (true) {
            $item instanceof User     => 'users_id',
            $item instanceof Ticket   => 'tickets_id',
            $item instanceof Resource => 'plugin_iam_resources_id',
            default                   => null,
        };
        if ($field === null || !self::canView()) {
            return [];
        }
        $rows = [];
        foreach (
            $DB->request([
                'FROM'  => $t,
                'WHERE' => ["$t.$field" => (int) $item->getID(), self::visibilityCriteria()],
                'ORDER' => ["$t.date_begin DESC", "$t.id DESC"],
            ]) as $r
        ) {
            $rows[] = $r;
        }
        return $rows;
    }

    private static function tabAllowed(CommonGLPI $item): bool
    {
        return ($item instanceof User || $item instanceof Ticket || $item instanceof Resource)
            && !$item->isNewItem()
            && self::canView()
            && $item->canViewItem();
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || !self::tabAllowed($item)) {
            return '';
        }
        $label = $item instanceof Resource ? self::getTypeName(Session::getPluralNumber()) : __('Grants (IAM)', 'iam');
        return self::createTabEntry($label, count(self::visibleRows($item)), null, self::getIcon());
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        // The tab loader calls this directly from the tab id: rights are checked here too
        if (!$item instanceof CommonDBTM || !self::tabAllowed($item)) {
            return false;
        }
        $rows = [];
        $roleNames = [];
        $resourceNames = [];
        foreach (self::visibleRows($item) as $r) {
            $roleId = (int) $r['plugin_iam_roles_id'];
            if (!isset($roleNames[$roleId])) {
                $role = new Role();
                $roleNames[$roleId] = $role->getFromDB($roleId)
                    ? ['name' => (string) $role->fields['name'], 'level' => (string) $role->fields['level']]
                    : ['name' => '#' . $roleId, 'level' => ''];
            }
            $resId = (int) $r['plugin_iam_resources_id'];
            $resourceNames[$resId] ??= (string) Dropdown::getDropdownName(Resource::getTable(), $resId);
            $ticket = (int) $r['tickets_id'];
            $rows[] = [
                'id'       => (int) $r['id'],
                'url'      => self::getFormURLWithID((int) $r['id']),
                'person'   => (string) User::getFriendlyNameById((int) $r['users_id']),
                'resource' => $resourceNames[$resId],
                'role'     => $roleNames[$roleId]['name'],
                'level'    => Role::levelLabels()[$roleNames[$roleId]['level']] ?? $roleNames[$roleId]['level'],
                'status'   => (string) $r['status'],
                'status_label' => self::statusLabels()[$r['status']] ?? (string) $r['status'],
                'begin'    => (string) $r['date_begin'],
                'end'      => (string) $r['date_end'],
                'ticket'   => $ticket > 0 && self::ticketAllowed($ticket) ? $ticket : 0,
                'source'   => self::sourceLabels()[$r['source']] ?? (string) $r['source'],
            ];
        }
        $param = match (true) {
            $item instanceof User   => 'users_id',
            $item instanceof Ticket => 'tickets_id',
            default                 => 'plugin_iam_resources_id',
        };
        $canAdd = self::canCreate() && !($item instanceof User && (int) $item->getID() === self::sessionUser())
            && !($item instanceof Resource && $item->isDeleted());
        TemplateRenderer::getInstance()->display('@iam/grants_tab.html.twig', [
            'rows'      => $rows,
            'for'       => $param,
            'can_add'   => $canAdd,
            'add_url'   => self::getFormURL() . '?' . $param . '=' . (int) $item->getID(),
        ]);
        return true;
    }
}
