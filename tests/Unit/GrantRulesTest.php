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

use GlpiPlugin\Iam\FieldSets;
use GlpiPlugin\Iam\GrantRules;
use GlpiPlugin\Iam\InputGuard;
use PHPUnit\Framework\TestCase;

final class GrantRulesTest extends TestCase
{
    /** @return array<string,mixed> */
    private static function add(array $extra = []): array
    {
        return $extra + ['status' => 'active', 'mfa' => 'na', 'date_begin' => '2026-01-01', 'tickets_id' => 12];
    }

    /** @return array<string,mixed> */
    private static function current(array $extra = []): array
    {
        return $extra + [
            'users_id' => 20, 'users_id_recorder' => 9, 'users_id_approver' => 0, 'users_id_approver_security' => 0,
            'status' => 'active', 'mfa' => 'na', 'date_begin' => '2026-01-01', 'date_end' => null, 'revoke_reason' => null,
            'justification' => '', 'tickets_id' => 12, 'plugin_accounts_accounts_id' => 0,
        ];
    }

    public function testSourceAgent(): void
    {
        $this->assertSame('agent', GrantRules::source(true, 'agent'));
        $this->assertSame('agent', GrantRules::source(false, 'agent'));
    }

    public function testSourceApi(): void
    {
        $this->assertSame('api', GrantRules::source(true, null));
        $this->assertSame('api', GrantRules::source(true, 'analyst'));
    }

    public function testSourceManual(): void
    {
        $this->assertSame('manual', GrantRules::source(false, null));
        $this->assertSame('manual', GrantRules::source(false, 'owner'));
    }

    public function testEndBeforeBegin(): void
    {
        $this->assertContains('date_order', GrantRules::validate(self::add(['date_end' => '2025-12-31']), false, null));
        $this->assertNotContains('date_order', GrantRules::validate(self::add(['date_end' => '2026-01-01']), false, null));
        // On update the stored begin date is compared with the new end date
        $this->assertContains('date_order', GrantRules::validate(['date_end' => '2025-06-01'], true, null, self::current()));
    }

    public function testInvalidDate(): void
    {
        $this->assertContains('date_invalid', GrantRules::validate(self::add(['date_end' => '2026-02-30']), false, null));
        $this->assertContains('date_invalid', GrantRules::validate(self::add(['date_begin' => "2026-01-01' OR 1"]), false, null));
    }

    public function testAgentNeedsTicket(): void
    {
        $this->assertContains('agent_cannot_activate_without_ticket', GrantRules::validate(self::add(['tickets_id' => 0]), false, 'agent'));
        $this->assertContains('agent_cannot_activate_without_ticket', GrantRules::validate(array_diff_key(self::add(), ['tickets_id' => 1]), false, 'agent'));
        $this->assertSame([], GrantRules::validate(self::add(), false, 'agent'));
        // Other profiles may register without a ticket (the missing ticket becomes a deviation)
        $this->assertSame([], GrantRules::validate(self::add(['tickets_id' => 0]), false, 'analyst'));
    }

    public function testAgentCannotRevoke(): void
    {
        $errors = GrantRules::validate(['status' => 'revoked', 'revoke_reason' => 'r'], true, 'agent', self::current());
        $this->assertContains('agent_cannot_approve', $errors);
        $this->assertSame([], GrantRules::validate(['status' => 'revoked', 'revoke_reason' => 'r'], true, 'analyst', self::current()));
    }

    public function testAgentCannotSetSecurityApprover(): void
    {
        $this->assertContains('agent_cannot_approve', GrantRules::validate(self::add(['users_id_approver_security' => 5]), false, 'agent'));
        $this->assertContains('agent_cannot_approve', GrantRules::validate(['users_id_approver_security' => 5], true, 'agent', self::current()));
        $this->assertNotContains('agent_cannot_approve', GrantRules::validate(self::add(['users_id_approver_security' => 0]), false, 'agent'));
    }

    public function testRevokeNeedsReason(): void
    {
        $this->assertContains('revoke_requires_reason', GrantRules::validate(['status' => 'revoked'], true, null, self::current()));
        $this->assertContains('revoke_requires_reason', GrantRules::validate(['status' => 'revoked', 'revoke_reason' => '   '], true, null, self::current()));
        $this->assertSame([], GrantRules::validate(['status' => 'revoked', 'revoke_reason' => 'Left the company'], true, null, self::current()));
    }

    public function testImmutableListContainsUserAndRole(): void
    {
        foreach (['users_id', 'plugin_iam_roles_id', 'plugin_iam_resources_id', 'entities_id', 'source', 'users_id_recorder', 'date_creation'] as $f) {
            $this->assertContains($f, GrantRules::IMMUTABLE);
        }
        $in = ['users_id' => 1, 'plugin_iam_roles_id' => 2, 'plugin_iam_resources_id' => 3, 'entities_id' => 4, 'source' => 'manual',
            'users_id_recorder' => 5, 'date_end' => '2027-01-01', 'date_revoked' => '2000-01-01', 'date_mod' => 'x', 'id' => 7];
        $this->assertSame(['date_end' => '2027-01-01'], InputGuard::filter($in, FieldSets::GRANT, FieldSets::GRANT_IMMUTABLE, true));
        // The revocation date and the audit dates never come from the input, not even on creation
        foreach (['date_revoked', 'date_mod', 'date_creation', 'id'] as $f) {
            $this->assertNotContains($f, FieldSets::GRANT);
        }
    }

    public function testStatusAndMfaEnums(): void
    {
        $this->assertContains('status_invalid', GrantRules::validate(self::add(['status' => 'approved']), false, null));
        $this->assertContains('mfa_invalid', GrantRules::validate(self::add(['mfa' => 'maybe']), false, null));
        foreach (['yes', 'no', 'na'] as $mfa) {
            $this->assertSame([], GrantRules::validate(self::add(['mfa' => $mfa]), false, null));
        }
    }

    public function testCreationStatuses(): void
    {
        $this->assertSame([], GrantRules::validate(self::add(['status' => 'pending']), false, null));
        foreach (['revoke_pending', 'modify_pending', 'revoked', 'expired'] as $s) {
            $this->assertContains('status_transition_invalid', GrantRules::validate(self::add(['status' => $s, 'revoke_reason' => 'r']), false, null), $s);
        }
    }

    public function testTransitions(): void
    {
        $allowed = [
            ['active', 'revoke_pending'], ['active', 'modify_pending'], ['active', 'revoked'], ['active', 'expired'],
            ['revoke_pending', 'active'], ['revoke_pending', 'revoked'], ['modify_pending', 'active'], ['modify_pending', 'revoked'],
            ['pending', 'active'], [null, 'active'], [null, 'pending'],
        ];
        foreach ($allowed as [$from, $to]) {
            $this->assertTrue(GrantRules::transitionAllowed($from, $to), "$from -> $to");
        }
        $refused = [
            ['revoked', 'active'], ['revoked', 'revoke_pending'], ['expired', 'active'], ['expired', 'revoked'],
            ['active', 'pending'], ['revoke_pending', 'modify_pending'], ['modify_pending', 'expired'], [null, 'revoked'],
            ['active', 'bogus'],
        ];
        foreach ($refused as [$from, $to]) {
            $this->assertFalse(GrantRules::transitionAllowed($from, $to), "$from -> $to");
        }
        $this->assertContains('status_transition_invalid', GrantRules::validate(['status' => 'active'], true, null, self::current(['status' => 'revoked'])));
        $this->assertContains('status_transition_invalid', GrantRules::validate(['status' => 'active'], true, null, self::current(['status' => 'expired'])));
    }

    public function testNoSelfService(): void
    {
        $this->assertContains('self_service', GrantRules::separation(['users_id' => 9, 'users_id_recorder' => 9], 9));
        $this->assertNotContains('self_service', GrantRules::separation(['users_id' => 20, 'users_id_recorder' => 9], 9));
        $this->assertContains('self_service', GrantRules::separation(['users_id' => 0], 0), 'anonymous sessions register nothing');
    }

    public function testApproverIsNotBeneficiary(): void
    {
        $this->assertContains('approver_is_beneficiary', GrantRules::separation(['users_id' => 20, 'users_id_approver' => 20], 9));
        $this->assertSame([], GrantRules::separation(['users_id' => 20, 'users_id_approver' => 21, 'users_id_recorder' => 9], 9));
    }

    public function testSecurityApproverIsNeitherBeneficiaryNorRequester(): void
    {
        $base = ['users_id' => 20, 'users_id_recorder' => 9];
        $this->assertContains('security_approver_conflict', GrantRules::separation($base + ['users_id_approver_security' => 20], 7));
        $this->assertContains('security_approver_conflict', GrantRules::separation($base + ['users_id_approver_security' => 9], 7));
        $this->assertSame([], GrantRules::separation($base + ['users_id_approver_security' => 7], 7));
    }

    public function testSecurityApproverNeedsApproveRight(): void
    {
        $this->assertSame(['security_approver_right'], GrantRules::approvalErrors(['users_id_approver_security' => 7], false));
        $this->assertSame(['security_approver_right'], GrantRules::approvalErrors(['users_id_approver_security' => 0], false), 'clearing it is an approval decision too');
        $this->assertSame([], GrantRules::approvalErrors(['users_id_approver_security' => 7], true));
        $this->assertSame([], GrantRules::approvalErrors(['date_end' => '2027-01-01'], false));
    }

    public function testChangesIgnoreUnchangedValues(): void
    {
        $changes = GrantRules::changes(
            ['date_end' => '', 'tickets_id' => '12', 'status' => 'revoke_pending', 'justification' => 'x', 'mfa' => 'na', 'plugin_accounts_accounts_id' => ''],
            self::current()
        );
        $this->assertSame(['status' => 'revoke_pending', 'justification' => 'x'], $changes);
    }

    public function testOwnerMayOnlyRequestRevocationOrModification(): void
    {
        $this->assertSame([], GrantRules::ownerErrors(['status' => 'revoke_pending', 'justification' => 'Not needed']));
        $this->assertSame([], GrantRules::ownerErrors(['status' => 'modify_pending']));
        $this->assertSame([], GrantRules::ownerErrors(['justification' => 'More context']));
        $this->assertContains('owner_field_forbidden', GrantRules::ownerErrors(['date_end' => '2030-01-01']));
        $this->assertContains('owner_field_forbidden', GrantRules::ownerErrors(['users_id_approver' => 3]));
        $this->assertContains('owner_field_forbidden', GrantRules::ownerErrors(['mfa' => 'yes']));
        $this->assertContains('owner_field_forbidden', GrantRules::ownerErrors(['plugin_accounts_accounts_id' => 4]));
        $this->assertContains('owner_status_forbidden', GrantRules::ownerErrors(['status' => 'revoked', 'revoke_reason' => 'r']));
        $this->assertContains('owner_status_forbidden', GrantRules::ownerErrors(['status' => 'active']));
    }
}
