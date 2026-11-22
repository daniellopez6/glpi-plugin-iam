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

use DBConnection;
use Migration;

/**
 * Creates, upgrades and removes the database objects of the plugin.
 */
final class Installer
{
    public static function install(Migration $m): void
    {
        global $DB;

        $charset   = DBConnection::getDefaultCharset();
        $collation = DBConnection::getDefaultCollation();
        $sign      = DBConnection::getDefaultPrimaryKeySignOption();

        foreach (Schema::tables($sign) as $table => $columns) {
            if (!$DB->tableExists($table)) {
                // Static DDL defined in Schema (no user data). GLPI 12 provides no API to create
                // tables; official plugins use the same mechanism.
                // nosemgrep: iam-sql-nonliteral
                $DB->doQuery("CREATE TABLE `$table` ($columns) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC");
            }
        }

        // Later releases add columns here with $m->addField()/addKey(), guarded by fieldExists().

        $m->executeMigration();
    }

    public static function uninstall(): void
    {
        global $DB;

        self::uninstallRights();
        foreach (array_reverse(array_keys(Schema::tables(''))) as $table) {
            $DB->dropTable($table, true);
        }
    }

    /**
     * Removal of the plugin rights and of the [iam:*] role profiles that have no users.
     */
    private static function uninstallRights(): void
    {
        // Task 3: filled in when the rights and the role profiles are created.
    }
}
