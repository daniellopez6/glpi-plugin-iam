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
 * Whitelist of GLPI itemtypes that can back an IAM resource.
 */
final class ResourceItemtypes
{
    /** @var list<string> */
    public const ALLOWED = [
        'Software',
        'Appliance',
        'Computer',
        'NetworkEquipment',
        'Database',
        'DatabaseInstance',
        'Domain',
        'Certificate',
        'Supplier',
    ];

    public static function isAllowed(string $itemtype): bool
    {
        return in_array($itemtype, self::ALLOWED, true);
    }
}
