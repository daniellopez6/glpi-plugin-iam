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
use GlpiPlugin\Iam\Profile as IamProfile;
use GlpiPlugin\Iam\Rights;
use Migration;
use Profile as GlpiProfile;
use ProfileRight;

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

        // Keys added after a table was first created (Migration::addKey() skips the existing ones)
        foreach (Schema::keys() as $table => $keys) {
            foreach ($keys as $name => $columns) {
                $m->addKey($table, $columns, $name);
            }
        }

        // Later releases add columns here with $m->addField(), guarded by fieldExists().

        self::installRights();

        $m->executeMigration();
    }

    /**
     * Creates the missing rights with their defaults by profile name (values already set by an
     * administrator are never overwritten) and the missing role profiles.
     */
    private static function installRights(): void
    {
        global $DB;

        foreach (Rights::all() as $right) {
            if (countElementsInTable('glpi_profilerights', ['name' => $right]) > 0) {
                continue;
            }
            ProfileRight::addProfileRights([$right]);
            foreach ($DB->request(['FROM' => 'glpi_profiles']) as $profile) {
                $value = Rights::initialValue((string) $profile['name'], (string) $profile['comment'], $right);
                if ($profile['interface'] !== 'central') {
                    $value = 0;
                }
                if ($value) {
                    ProfileRight::updateProfileRights((int) $profile['id'], [$right => $value]);
                }
            }
        }
        IamProfile::createRoleProfiles();
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
        global $DB;

        foreach (array_keys(Rights::roleProfiles()) as $key) {
            $rows = $DB->request([
                'SELECT' => 'id',
                'FROM'   => GlpiProfile::getTable(),
                'WHERE'  => ['comment' => ['LIKE', '%' . Rights::marker($key) . '%']],
            ]);
            foreach ($rows as $row) {
                if (countElementsInTable('glpi_profiles_users', ['profiles_id' => $row['id']]) === 0) {
                    (new GlpiProfile())->delete(['id' => $row['id']], true);
                }
            }
        }
        ProfileRight::deleteProfileRights(Rights::all());
    }
}
