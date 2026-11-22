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

namespace GlpiPlugin\Iam\Tests\Unit;

use GlpiPlugin\Iam\Install\Schema;
use PHPUnit\Framework\TestCase;

final class SchemaTest extends TestCase
{
    public function testEveryTableHasEntitiesId(): void
    {
        $this->assertCount(15, Schema::tables('unsigned'));
        foreach (Schema::tables('unsigned') as $table => $body) {
            $this->assertStringContainsString('`entities_id`', $body, $table);
            $this->assertStringContainsString('PRIMARY KEY (`id`)', $body, $table);
            $this->assertStringContainsString('int unsigned NOT NULL AUTO_INCREMENT', $body, $table);
        }
    }

    public function testScopeCoversEveryTable(): void
    {
        $this->assertSame(array_keys(Schema::tables('unsigned')), array_keys(Schema::scope()));
        foreach (Schema::scope() as $table => $scope) {
            $this->assertMatchesRegularExpression('/^(entity|parent:\w+:\w+)$/', $scope, $table);
        }
        $this->assertSame('parent:plugin_iam_resources_id:resources', Schema::scope()['glpi_plugin_iam_roles']);
    }

    public function testAppendOnlyTablesHaveNoDateMod(): void
    {
        $tables = Schema::tables('unsigned');
        foreach (Schema::APPEND_ONLY as $table) {
            $this->assertArrayHasKey($table, $tables);
            $this->assertStringNotContainsString('`date_mod`', $tables[$table], $table);
            $this->assertStringContainsString('`date_creation`', $tables[$table], $table);
        }
        $this->assertStringContainsString('`date_mod`', $tables['glpi_plugin_iam_grants']);
    }

    public function testGrantStatusesIncludePending(): void
    {
        $grants = Schema::tables('unsigned')['glpi_plugin_iam_grants'];
        $this->assertStringContainsString("'active'", $grants);
        $this->assertStringContainsString('pending', $grants);
        $this->assertStringContainsString('`users_id_approver_security`', $grants);
    }

    public function testPositionsRolesUnique(): void
    {
        $body = Schema::tables('unsigned')['glpi_plugin_iam_positions_roles'];
        $this->assertStringContainsString('UNIQUE KEY', $body);
        $this->assertStringContainsString('(`plugin_iam_positions_id`,`plugin_iam_roles_id`)', $body);
    }

    public function testSignIsApplied(): void
    {
        $this->assertStringContainsString('int NOT NULL AUTO_INCREMENT', Schema::tables('')['glpi_plugin_iam_notes']);
    }

    public function testEveryForeignKeyColumnLeadsAnIndex(): void
    {
        $keys = Schema::keys();
        foreach (Schema::tables('') as $table => $body) {
            preg_match_all('/^\s*`(\w+_id(?:_\w+)?)` int /m', $body, $m);
            $this->assertNotSame([], $m[1], $table);
            $leading = array_map(static fn (array $cols): string => $cols[0], $keys[$table]);
            // polymorphic links are indexed as (itemtype, items_id)
            if (in_array(['itemtype', 'items_id'], $keys[$table], true)) {
                $leading[] = 'items_id';
            }
            foreach (preg_split('/\n/', $body) ?: [] as $line) {
                if (preg_match('/UNIQUE KEY `\w+` \(`(\w+)`/', $line, $u) === 1) {
                    $leading[] = $u[1];
                }
            }
            foreach ($m[1] as $column) {
                $this->assertContains($column, $leading, "$table.$column has no index");
            }
        }
    }

    public function testKeysAreParsed(): void
    {
        $grants = Schema::keys()['glpi_plugin_iam_grants'];
        $this->assertSame(['users_id_approver'], $grants['users_id_approver']);
        $this->assertSame(['users_id_approver_security'], $grants['users_id_approver_security']);
        $this->assertSame(['users_id_recorder'], $grants['users_id_recorder']);
        $this->assertSame(['usertitles_id'], Schema::keys()['glpi_plugin_iam_positions']['usertitles_id']);
        $this->assertSame(['itemtype', 'items_id'], Schema::keys()['glpi_plugin_iam_resources']['item']);
        $this->assertArrayNotHasKey('unicity', Schema::keys()['glpi_plugin_iam_positions_roles']);
    }
}
