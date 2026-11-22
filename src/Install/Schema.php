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

namespace GlpiPlugin\Iam\Install;

/**
 * Table definitions of the plugin (releases 1.0 to 1.3). Pure: no GLPI calls, so it can be unit tested.
 */
final class Schema
{
    /** Tables that are only ever inserted: they have no date_mod and are never purged. */
    public const APPEND_ONLY = [
        'glpi_plugin_iam_notes',
        'glpi_plugin_iam_grantusages',
        'glpi_plugin_iam_reportlogs',
    ];

    private const PREFIX = 'glpi_plugin_iam_';

    /**
     * @param string $sign Sign option of the primary keys of GLPI (e.g. 'unsigned' or '')
     * @return array<string,string> table name => column and key definitions
     */
    public static function tables(string $sign): array
    {
        $sign = $sign === '' ? '' : $sign . ' ';
        $id  = "`id` int {$sign}NOT NULL AUTO_INCREMENT";
        $fk  = static fn (string $c): string => "`{$c}` int {$sign}NOT NULL DEFAULT '0'";
        $ent = $fk('entities_id');
        $str = static fn (string $c, int $len = 255, string $def = ''): string => "`{$c}` varchar({$len}) NOT NULL DEFAULT '{$def}'";
        $int = static fn (string $c, string $def = '0'): string => "`{$c}` tinyint NOT NULL DEFAULT '{$def}'";
        $dts = "`date_creation` timestamp NULL DEFAULT NULL,\n            `date_mod` timestamp NULL DEFAULT NULL";
        $dtc = '`date_creation` timestamp NULL DEFAULT NULL';
        $dn  = static fn (string $c): string => "`{$c}` date DEFAULT NULL";

        return [
            self::PREFIX . 'positions' => "
            {$id},
            `name` varchar(255) DEFAULT NULL,
            `completename` text,
            {$fk('plugin_iam_positions_id')},
            `level` int NOT NULL DEFAULT '0',
            `ancestors_cache` longtext,
            `sons_cache` longtext,
            {$ent},
            {$int('is_recursive', '1')},
            `comment` text,
            {$fk('usertitles_id')},
            {$fk('groups_id')},
            {$int('is_active', '1')},
            {$dts},
            PRIMARY KEY (`id`),
            KEY `name` (`name`),
            KEY `plugin_iam_positions_id` (`plugin_iam_positions_id`),
            KEY `entities_id` (`entities_id`),
            KEY `groups_id` (`groups_id`)",

            self::PREFIX . 'positions_users' => "
            {$id},
            {$fk('plugin_iam_positions_id')},
            {$fk('users_id')},
            {$int('is_primary')},
            {$str('type', 16, 'holder')},
            {$dn('date_begin')},
            {$dn('date_end')},
            {$fk('tickets_id')},
            {$ent},
            {$dts},
            PRIMARY KEY (`id`),
            KEY `plugin_iam_positions_id` (`plugin_iam_positions_id`),
            KEY `users_id` (`users_id`),
            KEY `tickets_id` (`tickets_id`),
            KEY `entities_id` (`entities_id`)",

            self::PREFIX . 'resources' => "
            {$id},
            `name` varchar(255) DEFAULT NULL,
            {$str('code', 32)},
            {$ent},
            {$int('is_recursive')},
            {$int('is_deleted')},
            {$str('itemtype', 100)},
            {$fk('items_id')},
            {$fk('users_id_owner')},
            {$fk('groups_id_owner')},
            {$str('criticality', 16)},
            {$str('review_frequency', 16, 'annual')},
            `comment` text,
            {$dts},
            PRIMARY KEY (`id`),
            KEY `name` (`name`),
            KEY `code` (`code`),
            KEY `entities_id` (`entities_id`),
            KEY `is_deleted` (`is_deleted`),
            KEY `item` (`itemtype`,`items_id`),
            KEY `users_id_owner` (`users_id_owner`),
            KEY `groups_id_owner` (`groups_id_owner`)",

            self::PREFIX . 'roles' => "
            {$id},
            {$fk('plugin_iam_resources_id')},
            {$ent},
            `name` varchar(255) DEFAULT NULL,
            {$str('level', 16, 'standard')},
            {$int('is_breakglass')},
            `comment` text,
            {$dts},
            PRIMARY KEY (`id`),
            KEY `name` (`name`),
            KEY `plugin_iam_resources_id` (`plugin_iam_resources_id`),
            KEY `entities_id` (`entities_id`)",

            self::PREFIX . 'positions_roles' => "
            {$id},
            {$fk('plugin_iam_positions_id')},
            {$fk('plugin_iam_roles_id')},
            {$str('expectation', 16, 'allowed')},
            {$ent},
            `comment` text,
            {$dts},
            PRIMARY KEY (`id`),
            UNIQUE KEY `unicity` (`plugin_iam_positions_id`,`plugin_iam_roles_id`),
            KEY `plugin_iam_roles_id` (`plugin_iam_roles_id`),
            KEY `entities_id` (`entities_id`)",

            self::PREFIX . 'grants' => "
            {$id},
            {$fk('users_id')},
            {$fk('plugin_iam_roles_id')},
            {$fk('plugin_iam_resources_id')},
            {$ent},
            {$fk('plugin_accounts_accounts_id')},
            {$dn('date_begin')},
            {$dn('date_end')},
            {$fk('tickets_id')},
            {$fk('users_id_approver')},
            {$fk('users_id_approver_security')},
            `justification` text,
            {$str('mfa', 8, 'na')},
            {$str('status', 24, 'active')} COMMENT 'pending,active,revoke_pending,modify_pending,revoked,expired',
            `date_revoked` timestamp NULL DEFAULT NULL,
            `revoke_reason` text,
            {$str('source', 8, 'manual')},
            {$fk('users_id_recorder')},
            {$dts},
            PRIMARY KEY (`id`),
            KEY `users_id` (`users_id`),
            KEY `plugin_iam_roles_id` (`plugin_iam_roles_id`),
            KEY `plugin_iam_resources_id` (`plugin_iam_resources_id`),
            KEY `entities_id` (`entities_id`),
            KEY `plugin_accounts_accounts_id` (`plugin_accounts_accounts_id`),
            KEY `tickets_id` (`tickets_id`),
            KEY `status` (`status`),
            KEY `date_end` (`date_end`)",

            self::PREFIX . 'notes' => "
            {$id},
            {$str('itemtype', 100)},
            {$fk('items_id')},
            {$ent},
            {$fk('users_id')},
            `content` text,
            {$fk('plugin_iam_notes_id')},
            {$dtc},
            PRIMARY KEY (`id`),
            KEY `item` (`itemtype`,`items_id`),
            KEY `entities_id` (`entities_id`),
            KEY `users_id` (`users_id`),
            KEY `plugin_iam_notes_id` (`plugin_iam_notes_id`)",

            self::PREFIX . 'grantusages' => "
            {$id},
            {$fk('plugin_iam_grants_id')},
            {$ent},
            `date_use` timestamp NULL DEFAULT NULL,
            {$fk('tickets_id')},
            {$fk('users_id')},
            `reason` text,
            {$dtc},
            PRIMARY KEY (`id`),
            KEY `plugin_iam_grants_id` (`plugin_iam_grants_id`),
            KEY `entities_id` (`entities_id`),
            KEY `tickets_id` (`tickets_id`),
            KEY `users_id` (`users_id`),
            KEY `date_use` (`date_use`)",

            self::PREFIX . 'sodrules' => "
            {$id},
            `name` varchar(255) DEFAULT NULL,
            {$ent},
            {$int('is_recursive')},
            {$fk('plugin_iam_roles_id_a')},
            {$fk('plugin_iam_roles_id_b')},
            {$str('severity', 16)},
            `rationale` text,
            {$int('is_active', '1')},
            {$dts},
            PRIMARY KEY (`id`),
            KEY `name` (`name`),
            KEY `entities_id` (`entities_id`),
            KEY `plugin_iam_roles_id_a` (`plugin_iam_roles_id_a`),
            KEY `plugin_iam_roles_id_b` (`plugin_iam_roles_id_b`)",

            self::PREFIX . 'deviations' => "
            {$id},
            {$str('type', 32)},
            {$ent},
            {$fk('users_id')},
            {$fk('plugin_iam_roles_id')},
            {$fk('plugin_iam_resources_id')},
            {$fk('plugin_iam_grants_id')},
            {$fk('plugin_iam_sodrules_id')},
            {$str('severity', 16)},
            {$str('status', 16, 'open')},
            {$fk('waivers_id')},
            {$fk('users_id_assigned')},
            `date_detected` timestamp NULL DEFAULT NULL,
            `date_resolved` timestamp NULL DEFAULT NULL,
            {$str('fingerprint', 64)},
            {$dts},
            PRIMARY KEY (`id`),
            UNIQUE KEY `fingerprint` (`fingerprint`),
            KEY `entities_id` (`entities_id`),
            KEY `users_id` (`users_id`),
            KEY `plugin_iam_roles_id` (`plugin_iam_roles_id`),
            KEY `plugin_iam_resources_id` (`plugin_iam_resources_id`),
            KEY `plugin_iam_grants_id` (`plugin_iam_grants_id`),
            KEY `plugin_iam_sodrules_id` (`plugin_iam_sodrules_id`),
            KEY `waivers_id` (`waivers_id`),
            KEY `users_id_assigned` (`users_id_assigned`),
            KEY `status` (`status`)",

            self::PREFIX . 'campaigns' => "
            {$id},
            `name` varchar(255) DEFAULT NULL,
            {$ent},
            {$dn('date_begin')},
            {$dn('date_end')},
            {$str('status', 16, 'draft')},
            {$fk('users_id_launcher')},
            `date_closed` timestamp NULL DEFAULT NULL,
            `comment` text,
            {$dts},
            PRIMARY KEY (`id`),
            KEY `name` (`name`),
            KEY `entities_id` (`entities_id`),
            KEY `status` (`status`),
            KEY `users_id_launcher` (`users_id_launcher`)",

            self::PREFIX . 'campaignitems' => "
            {$id},
            {$fk('plugin_iam_campaigns_id')},
            {$fk('plugin_iam_grants_id')},
            {$ent},
            {$str('decision', 16, 'pending')},
            {$fk('users_id_decider')},
            `date_decision` timestamp NULL DEFAULT NULL,
            {$fk('tickets_id_child')},
            {$dts},
            PRIMARY KEY (`id`),
            KEY `plugin_iam_campaigns_id` (`plugin_iam_campaigns_id`),
            KEY `plugin_iam_grants_id` (`plugin_iam_grants_id`),
            KEY `entities_id` (`entities_id`),
            KEY `decision` (`decision`),
            KEY `users_id_decider` (`users_id_decider`),
            KEY `tickets_id_child` (`tickets_id_child`)",

            self::PREFIX . 'snapshots' => "
            {$id},
            {$ent},
            `date_snapshot` date DEFAULT NULL,
            `payload` longtext,
            `sha256` char(64) NOT NULL DEFAULT '',
            {$dts},
            PRIMARY KEY (`id`),
            KEY `entities_id` (`entities_id`),
            KEY `date_snapshot` (`date_snapshot`)",

            self::PREFIX . 'reportlogs' => "
            {$id},
            {$ent},
            {$fk('users_id')},
            {$str('report', 64)},
            `filters` text,
            `sha256` char(64) NOT NULL DEFAULT '',
            {$dtc},
            PRIMARY KEY (`id`),
            KEY `entities_id` (`entities_id`),
            KEY `users_id` (`users_id`),
            KEY `report` (`report`)",

            self::PREFIX . 'entityconfigs' => "
            {$id},
            {$ent},
            {$str('code_prefix', 16)},
            `priv_max_days` int NOT NULL DEFAULT '-2',
            {$str('review_standard', 16)},
            {$str('review_privileged', 16)},
            `require_mfa_privileged` tinyint NOT NULL DEFAULT '-2',
            {$dts},
            PRIMARY KEY (`id`),
            UNIQUE KEY `entities_id` (`entities_id`)",
        ];
    }

    /**
     * How the entity of each table is determined: its own column ('entity') or copied from its parent.
     *
     * @return array<string,string> table => 'entity' | 'parent:<fk column>:<parent table>'
     */
    public static function scope(): array
    {
        $scope = [];
        foreach (
            ['positions', 'positions_users', 'resources', 'positions_roles', 'grants', 'notes', 'grantusages',
                  'sodrules', 'deviations', 'campaigns', 'campaignitems', 'snapshots', 'reportlogs', 'entityconfigs'] as $t
        ) {
            $scope[self::PREFIX . $t] = 'entity';
        }
        $scope[self::PREFIX . 'roles'] = 'parent:plugin_iam_resources_id:resources';
        // Keep the order of tables()
        return array_replace(array_flip(array_keys(self::tables(''))), $scope);
    }
}
