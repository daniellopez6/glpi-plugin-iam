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

/**
 * Input whitelists of the plugin items (pure). The id, is_deleted and the audit dates never come from the input:
 * is_deleted only changes through delete()/restore().
 */
final class FieldSets
{
    /** @var list<string> */
    public const RESOURCE = ['name', 'code', 'entities_id', 'is_recursive', 'itemtype', 'items_id',
        'users_id_owner', 'groups_id_owner', 'criticality', 'review_frequency', 'comment'];
    /** @var list<string> */
    public const RESOURCE_IMMUTABLE = ['entities_id', 'is_recursive'];
    /** @var list<string> */
    public const ROLE = ['plugin_iam_resources_id', 'entities_id', 'name', 'level', 'is_breakglass', 'comment'];
    /** @var list<string> */
    public const ROLE_IMMUTABLE = ['plugin_iam_resources_id', 'entities_id'];
    /** @var list<string> */
    public const POSITION_ROLE = ['plugin_iam_positions_id', 'plugin_iam_roles_id', 'entities_id', 'expectation', 'comment'];
    /** @var list<string> */
    public const POSITION_ROLE_IMMUTABLE = ['plugin_iam_positions_id', 'plugin_iam_roles_id', 'entities_id'];
    /**
     * Grant fields accepted from the input. date_revoked is set by the server when the status becomes revoked;
     * plugin_iam_resources_id, entities_id, source and users_id_recorder are overwritten by the server on creation.
     *
     * @var list<string>
     */
    public const GRANT = ['users_id', 'plugin_iam_roles_id', 'plugin_iam_resources_id', 'entities_id', 'plugin_accounts_accounts_id',
        'date_begin', 'date_end', 'tickets_id', 'users_id_approver', 'users_id_approver_security', 'justification', 'mfa', 'status',
        'revoke_reason', 'source', 'users_id_recorder'];
    /** @var list<string> */
    public const GRANT_IMMUTABLE = GrantRules::IMMUTABLE;
}
