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

use Profile as GlpiProfile;
use Session;

/**
 * Rights model of the IAM plugin.
 *
 * - plugin_iam           Access register (grants, deviations, notes): READ (all) or READ_OWNED (own only),
 *                        CREATE, UPDATE / UPDATE_OWNED. Nothing is ever deleted or purged.
 * - plugin_iam_config    Positions, resources, roles, access matrix and SoD rules.
 * - plugin_iam_review    Recertification campaigns: review items (UPDATE).
 * - plugin_iam_approve   Approval of access requests and deviations (UPDATE).
 * - plugin_iam_report    Reports and exports (READ).
 */
final class Rights
{
    public const ACCESS  = 'plugin_iam';
    public const CONFIG  = 'plugin_iam_config';
    public const REVIEW  = 'plugin_iam_review';
    public const APPROVE = 'plugin_iam_approve';
    public const REPORT  = 'plugin_iam_report';

    /** @return list<string> */
    public static function all(): array
    {
        return [self::ACCESS, self::CONFIG, self::REVIEW, self::APPROVE, self::REPORT];
    }

    public static function canReadAll(): bool
    {
        return (bool) Session::haveRight(self::ACCESS, READ);
    }

    /** The user can only see own records. */
    public static function onlyOwn(): bool
    {
        return !self::canReadAll() && Session::haveRight(self::ACCESS, READ_OWNED);
    }

    /** Key of the IAM role profile ([iam:key] marker in the comment) that is active in the session, if any. */
    public static function activeRoleKey(): ?string
    {
        $id = (int) ($_SESSION['glpiactiveprofile']['id'] ?? 0);
        if ($id <= 0) {
            return null;
        }
        $profile = new GlpiProfile();
        if (!$profile->getFromDB($id)) {
            return null;
        }
        return self::keyFromComment((string) ($profile->fields['comment'] ?? ''));
    }

    public static function keyFromComment(string $comment): ?string
    {
        return preg_match('/\[iam:([a-z]+)\]/', $comment, $m) === 1 ? $m[1] : null;
    }

    /** Marker stored in the comment of a role profile. */
    public static function marker(string $key): string
    {
        return '[iam:' . $key . ']';
    }

    /**
     * Default values at install/update time, by standard GLPI profile name. Only Super-Admin and Admin get
     * access; every other profile (including unknown ones) gets nothing, and nobody can delete or purge.
     *
     * @return array<string,int>
     */
    public static function defaults(string $profile): array
    {
        $full = [
            self::ACCESS  => READ | READ_OWNED | CREATE | UPDATE | UPDATE_OWNED,
            self::CONFIG  => ALLSTANDARDRIGHT,
            self::REVIEW  => UPDATE,
            self::APPROVE => UPDATE,
            self::REPORT  => READ,
        ];
        return match ($profile) {
            'Super-Admin' => $full,
            'Admin'       => [self::APPROVE => 0] + $full,
            default       => array_fill_keys(self::all(), 0),
        };
    }

    /**
     * Ready-to-assign role profiles created at installation, recognised by the [iam:key] marker that ends their comment.
     *
     * @return array<string, array{name:string, comment:string, rights:array<string,int>}>
     */
    public static function roleProfiles(): array
    {
        // Minimal GLPI navigation: no inventory, no tickets
        $base = ['knowbase' => READ, 'personalization' => READ | UPDATE, 'password_update' => 1, 'document' => READ];
        $roles = [
            'analyst' => [
                'name'    => 'IAM - Analista',
                'comment' => __('Maintains the access governance catalogue and register: positions, resources, roles, access matrix and grants. Does not review or approve.', 'iam'),
                'rights'  => $base + [self::ACCESS => READ | CREATE | UPDATE, self::CONFIG => READ | CREATE | UPDATE,
                    self::REVIEW => 0, self::APPROVE => 0, self::REPORT => READ],
            ],
            'owner' => [
                'name'    => 'IAM - Dueño de activo',
                'comment' => __('Sees and updates only the accesses of the resources they own and recertifies them.', 'iam'),
                'rights'  => $base + [self::ACCESS => READ_OWNED | UPDATE_OWNED, self::CONFIG => 0,
                    self::REVIEW => UPDATE, self::APPROVE => 0, self::REPORT => 0],
            ],
            'auditor' => [
                'name'    => 'IAM - Auditor',
                'comment' => __('Read-only access to the whole register, the catalogue and the reports.', 'iam'),
                'rights'  => $base + [self::ACCESS => READ, self::CONFIG => READ,
                    self::REVIEW => 0, self::APPROVE => 0, self::REPORT => READ],
            ],
            'agent' => [
                'name'    => 'IAM - Agente',
                'comment' => __('Registers access requests and grants and reads the catalogue. Cannot review or approve.', 'iam'),
                'rights'  => $base + [self::ACCESS => READ | CREATE, self::CONFIG => READ,
                    self::REVIEW => 0, self::APPROVE => 0, self::REPORT => 0],
            ],
        ];
        foreach ($roles as $key => $role) {
            $roles[$key]['comment'] .= ' ' . self::marker($key);
        }
        return $roles;
    }
}
