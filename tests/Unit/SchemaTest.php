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
}
