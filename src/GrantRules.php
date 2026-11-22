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
 * Business rules of the access register (pure logic: the caller passes the session facts it read).
 *
 * Security rests on the rights bits checked by Grant. The role key (the [iam:key] marker of the active profile)
 * only labels the provenance and adds defence in depth for the agent: removing a marker never grants anything.
 */
final class GrantRules
{
    /** Fields fixed at creation: corrections are made by revoking and registering a new grant. */
    public const IMMUTABLE = ['users_id', 'plugin_iam_roles_id', 'plugin_iam_resources_id', 'entities_id', 'source', 'users_id_recorder', 'date_creation'];

    public const STATUSES = ['pending', 'active', 'revoke_pending', 'modify_pending', 'revoked', 'expired'];
    public const MFA = ['yes', 'no', 'na'];

    /**
     * Status workflow of 1.0. null is the creation. revoked and expired are terminal.
     * pending (in-plugin request circuit, reserved) can be activated or rejected (revoked).
     */
    public const TRANSITIONS = [
        ''               => ['active', 'pending'],
        'pending'        => ['active', 'revoked'],
        'active'         => ['revoke_pending', 'modify_pending', 'revoked', 'expired'],
        'revoke_pending' => ['active', 'revoked'],
        'modify_pending' => ['active', 'revoked'],
        'revoked'        => [],
        'expired'        => [],
    ];

    /** What an owner (UPDATE_OWNED without UPDATE) may change: a revocation or modification request. */
    public const OWNER_FIELDS = ['status', 'justification'];
    public const OWNER_STATUSES = ['revoke_pending', 'modify_pending'];

    /** Provenance label of a new grant. */
    public static function source(bool $isApi, ?string $roleKey): string
    {
        if ($roleKey === 'agent') {
            return 'agent';
        }
        return $isApi ? 'api' : 'manual';
    }

    public static function transitionAllowed(?string $from, string $to): bool
    {
        return in_array($to, self::TRANSITIONS[$from ?? ''] ?? [], true);
    }

    /**
     * Validates the values of an add (whole input) or of an update ($input = changed fields, $current = stored row).
     *
     * @param array<string,mixed> $input
     * @param array<string,mixed> $current
     *
     * @return list<string> error codes: date_invalid, date_order, status_invalid, status_transition_invalid,
     *                      mfa_invalid, agent_cannot_activate_without_ticket, agent_cannot_approve, revoke_requires_reason
     */
    public static function validate(array $input, bool $isUpdate, ?string $roleKey, array $current = []): array
    {
        $errors = [];
        $merged = $isUpdate ? array_merge($current, $input) : $input;

        $begin = self::blankToNull($merged['date_begin'] ?? null);
        $end = self::blankToNull($merged['date_end'] ?? null);
        if (($begin !== null && !PositionPeriod::isValidDate($begin)) || ($end !== null && !PositionPeriod::isValidDate($end))) {
            $errors[] = 'date_invalid';
        } elseif ($begin !== null && $end !== null && $end < $begin) {
            $errors[] = 'date_order';
        }

        $statusChanged = array_key_exists('status', $input);
        $status = (string) ($input['status'] ?? '');
        if ($statusChanged) {
            if (!InputGuard::enum($status, self::STATUSES)) {
                $errors[] = 'status_invalid';
            } elseif (!self::transitionAllowed($isUpdate ? (string) ($current['status'] ?? '') : null, $status)) {
                $errors[] = 'status_transition_invalid';
            }
        }

        if (array_key_exists('mfa', $input) && !InputGuard::enum((string) $input['mfa'], self::MFA)) {
            $errors[] = 'mfa_invalid';
        }

        if ($roleKey === 'agent') {
            if (!$isUpdate && (int) ($input['tickets_id'] ?? 0) <= 0) {
                $errors[] = 'agent_cannot_activate_without_ticket';
            }
            if ((int) ($input['users_id_approver_security'] ?? 0) > 0 || ($statusChanged && $status === 'revoked')) {
                $errors[] = 'agent_cannot_approve';
            }
        }

        if ($statusChanged && $status === 'revoked' && trim((string) ($merged['revoke_reason'] ?? '')) === '') {
            $errors[] = 'revoke_requires_reason';
        }
        return $errors;
    }

    /**
     * Separation of duties on the resulting row: nobody registers or edits their own access, the approver is not the
     * beneficiary, and the security approver is neither the beneficiary nor the requester (recorder).
     *
     * @param array<string,mixed> $merged
     *
     * @return list<string> error codes: self_service, approver_is_beneficiary, security_approver_conflict
     */
    public static function separation(array $merged, int $sessionUser): array
    {
        $errors = [];
        $beneficiary = (int) ($merged['users_id'] ?? 0);
        if ($sessionUser <= 0 || $beneficiary === $sessionUser) {
            $errors[] = 'self_service';
        }
        $approver = (int) ($merged['users_id_approver'] ?? 0);
        if ($approver > 0 && $approver === $beneficiary) {
            $errors[] = 'approver_is_beneficiary';
        }
        $security = (int) ($merged['users_id_approver_security'] ?? 0);
        if ($security > 0 && ($security === $beneficiary || $security === (int) ($merged['users_id_recorder'] ?? 0))) {
            $errors[] = 'security_approver_conflict';
        }
        return $errors;
    }

    /**
     * Setting, changing or clearing the security approver is a security approval (Rights::APPROVE UPDATE).
     *
     * @param array<string,mixed> $changes
     *
     * @return list<string>
     */
    public static function approvalErrors(array $changes, bool $canApprove): array
    {
        return array_key_exists('users_id_approver_security', $changes) && !$canApprove ? ['security_approver_right'] : [];
    }

    /**
     * Restrictions of an owner: only a revocation/modification request and its justification.
     *
     * @param array<string,mixed> $changes
     *
     * @return list<string> error codes: owner_field_forbidden, owner_status_forbidden
     */
    public static function ownerErrors(array $changes): array
    {
        $errors = [];
        if (array_diff(array_keys($changes), self::OWNER_FIELDS) !== []) {
            $errors[] = 'owner_field_forbidden';
        }
        if (array_key_exists('status', $changes) && !InputGuard::enum((string) $changes['status'], self::OWNER_STATUSES)) {
            $errors[] = 'owner_status_forbidden';
        }
        return $errors;
    }

    /**
     * Fields of the input whose value differs from the stored one (forms post every field; only real changes count).
     *
     * @param array<string,mixed> $input
     * @param array<string,mixed> $current
     *
     * @return array<string,mixed>
     */
    public static function changes(array $input, array $current): array
    {
        $out = [];
        foreach ($input as $key => $value) {
            if (self::normalized($key, $value) !== self::normalized($key, $current[$key] ?? null)) {
                $out[$key] = $value;
            }
        }
        return $out;
    }

    private static function normalized(string $key, mixed $value): string
    {
        // Foreign keys: '' / null / '0' all mean "none"
        if (str_ends_with($key, '_id') || str_contains($key, '_id_')) {
            return (string) (int) $value;
        }
        return trim(is_scalar($value) ? (string) $value : '');
    }

    private static function blankToNull(mixed $value): ?string
    {
        $v = is_scalar($value) ? trim((string) $value) : '';
        return $v === '' ? null : $v;
    }
}
