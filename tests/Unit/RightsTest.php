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

use GlpiPlugin\Iam\Rights;
use PHPUnit\Framework\TestCase;

final class RightsTest extends TestCase
{
    private const PROFILES = ['Super-Admin', 'Admin', 'Supervisor', 'Technician', 'Hotliner', 'Observer',
                              'Self-Service', 'Read-Only', 'Custom'];

    public function testTechnicianSeesNothing(): void
    {
        foreach (Rights::defaults('Technician') as $right => $value) {
            $this->assertSame(0, $value, $right);
        }
        $this->assertSame(Rights::all(), array_keys(Rights::defaults('Technician')));
    }

    public function testNonAdminStandardProfilesAndUnknownGetNothing(): void
    {
        foreach (['Hotliner', 'Supervisor', 'Observer', 'Self-Service', 'Read-Only', 'Whatever'] as $name) {
            $this->assertSame(0, array_sum(Rights::defaults($name)), $name);
        }
    }

    public function testSuperAdminAndAdmin(): void
    {
        $super = Rights::defaults('Super-Admin');
        $admin = Rights::defaults('Admin');
        $this->assertSame(READ | READ_OWNED | CREATE | UPDATE | UPDATE_OWNED, $super[Rights::ACCESS]);
        $this->assertSame(ALLSTANDARDRIGHT, $super[Rights::CONFIG]);
        $this->assertSame(UPDATE, $super[Rights::REVIEW]);
        $this->assertSame(UPDATE, $super[Rights::APPROVE]);
        $this->assertSame(READ, $super[Rights::REPORT]);
        $this->assertSame(0, $admin[Rights::APPROVE]);
        unset($super[Rights::APPROVE], $admin[Rights::APPROVE]);
        $this->assertSame($super, $admin);
    }

    public function testNoProfileCanPurgeAccessRecords(): void
    {
        $sets = [];
        foreach (self::PROFILES as $name) {
            $sets[$name] = Rights::defaults($name);
        }
        foreach (Rights::roleProfiles() as $key => $role) {
            $sets[$key] = $role['rights'];
        }
        foreach ($sets as $name => $rights) {
            $this->assertSame(0, $rights[Rights::ACCESS] & PURGE, $name);
            $this->assertSame(0, $rights[Rights::ACCESS] & DELETE, $name);
        }
    }

    public function testRoleProfileDefinitions(): void
    {
        $roles = Rights::roleProfiles();
        $this->assertSame(['analyst', 'owner', 'auditor', 'agent'], array_keys($roles));
        $this->assertSame(
            ['IAM - Analista', 'IAM - Dueño de activo', 'IAM - Auditor', 'IAM - Agente'],
            array_column($roles, 'name')
        );
        foreach ($roles as $key => $role) {
            $this->assertStringContainsString('[iam:' . $key . ']', $role['comment']);
            $this->assertSame(Rights::all(), array_keys(array_intersect_key($role['rights'], array_flip(Rights::all()))));
        }
    }

    public function testAnalyst(): void
    {
        $r = Rights::roleProfiles()['analyst']['rights'];
        $this->assertSame(READ | CREATE | UPDATE, $r[Rights::ACCESS]);
        $this->assertSame(READ | CREATE | UPDATE, $r[Rights::CONFIG]);
        $this->assertSame(0, $r[Rights::REVIEW]);
        $this->assertSame(0, $r[Rights::APPROVE]);
        $this->assertSame(READ, $r[Rights::REPORT]);
    }

    public function testOwnerProfileIsOwnOnly(): void
    {
        $r = Rights::roleProfiles()['owner']['rights'];
        $this->assertSame(READ_OWNED | UPDATE_OWNED, $r[Rights::ACCESS]);
        $this->assertSame(0, $r[Rights::ACCESS] & READ);
        $this->assertSame(UPDATE, $r[Rights::REVIEW]);
        $this->assertSame(0, $r[Rights::CONFIG]);
    }

    public function testAuditorIsReadOnly(): void
    {
        $r = Rights::roleProfiles()['auditor']['rights'];
        $this->assertSame(READ, $r[Rights::ACCESS]);
        $this->assertSame(READ, $r[Rights::CONFIG]);
        $this->assertSame(READ, $r[Rights::REPORT]);
        $this->assertSame(0, $r[Rights::REVIEW]);
        $this->assertSame(0, $r[Rights::APPROVE]);
    }

    public function testAgentCannotApproveOrReview(): void
    {
        $r = Rights::roleProfiles()['agent']['rights'];
        $this->assertSame(READ | CREATE, $r[Rights::ACCESS]);
        $this->assertSame(0, $r[Rights::APPROVE]);
        $this->assertSame(0, $r[Rights::REVIEW]);
        $this->assertSame(READ, $r[Rights::CONFIG]);
    }

    public function testWhoRegistersGrantsSeesTickets(): void
    {
        $roles = Rights::roleProfiles();
        $this->assertSame(1024, $roles['agent']['rights']['ticket']);
        $this->assertSame(1024, $roles['analyst']['rights']['ticket']);
        $this->assertArrayNotHasKey('ticket', $roles['owner']['rights']);
        $this->assertArrayNotHasKey('ticket', $roles['auditor']['rights']);
    }

    public function testInitialValueUsesRoleDefinitionForRoleProfiles(): void
    {
        $comment = 'Whatever ' . Rights::marker('agent');
        $this->assertSame(READ | CREATE, Rights::initialValue('IAM - Agente', $comment, Rights::ACCESS));
        $this->assertSame(READ, Rights::initialValue('Renamed', $comment, Rights::CONFIG));
        $this->assertSame(0, Rights::initialValue('IAM - Agente', $comment, Rights::APPROVE));
        $this->assertSame(UPDATE, Rights::initialValue('x', Rights::marker('owner'), Rights::REVIEW));
    }

    public function testInitialValueFallsBackToDefaultsByName(): void
    {
        $this->assertSame(0, Rights::initialValue('Technician', '', Rights::ACCESS));
        $this->assertSame(ALLSTANDARDRIGHT, Rights::initialValue('Super-Admin', 'plain', Rights::CONFIG));
        $this->assertSame(0, Rights::initialValue('Admin', '[iam:nonexistent]', Rights::APPROVE));
        $this->assertSame(UPDATE, Rights::initialValue('Super-Admin', '[iam:nonexistent]', Rights::APPROVE));
        $this->assertSame(0, Rights::initialValue('Custom', '', 'unknown_right'));
    }
}
