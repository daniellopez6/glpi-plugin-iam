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
}
