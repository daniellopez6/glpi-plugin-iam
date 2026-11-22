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
 * Validity period and consistency rules of person-position assignments (pure logic).
 */
final class PositionPeriod
{
    public const TYPES = ['holder', 'substitute', 'temporary'];

    /** Fields of an existing assignment that can still change; the rest is corrected by closing it and creating a new one. */
    public const UPDATABLE = ['date_end', 'tickets_id'];

    /**
     * Input of an update reduced to the updatable fields (and the id).
     *
     * @param array<string, mixed> $input
     *
     * @return array<string, mixed>
     */
    public static function filterUpdate(array $input): array
    {
        return array_intersect_key($input, array_flip(array_merge(['id'], self::UPDATABLE)));
    }

    /** Whether the period includes today (begin null or <= today; end null or >= today). Dates are 'Y-m-d'. */
    public static function isActive(?string $dateBegin, ?string $dateEnd, string $today): bool
    {
        $begin = self::normalize($dateBegin);
        $end   = self::normalize($dateEnd);
        return ($begin === null || $begin <= $today) && ($end === null || $end >= $today);
    }

    /** Strict 'Y-m-d' check (real calendar date, no trailing data). */
    public static function isValidDate(string $value): bool
    {
        $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $value);
        return $d !== false && $d->format('Y-m-d') === $value;
    }

    /**
     * @param array<string, mixed>            $input                 type, is_primary, date_begin, date_end
     * @param list<array<string, mixed>>      $otherActiveRowsOfUser other assignments of the same user
     *
     * @return list<string> error codes: type_invalid, date_invalid, date_order, primary_duplicate
     */
    public static function validate(array $input, array $otherActiveRowsOfUser, string $today): array
    {
        $errors = [];
        if (!in_array((string) ($input['type'] ?? ''), self::TYPES, true)) {
            $errors[] = 'type_invalid';
        }
        $begin = self::normalize(isset($input['date_begin']) ? (string) $input['date_begin'] : null);
        $end   = self::normalize(isset($input['date_end']) ? (string) $input['date_end'] : null);
        $datesOk = ($begin === null || self::isValidDate($begin)) && ($end === null || self::isValidDate($end));
        if (!$datesOk) {
            $errors[] = 'date_invalid';
            return $errors;
        }
        if ($begin !== null && $end !== null && $end < $begin) {
            $errors[] = 'date_order';
        }
        if ((int) ($input['is_primary'] ?? 0) === 1 && self::isActive($begin, $end, $today)) {
            foreach ($otherActiveRowsOfUser as $row) {
                if (
                    (int) ($row['is_primary'] ?? 0) === 1
                    && self::isActive(
                        self::normalize(isset($row['date_begin']) ? (string) $row['date_begin'] : null),
                        self::normalize(isset($row['date_end']) ? (string) $row['date_end'] : null),
                        $today
                    )
                ) {
                    $errors[] = 'primary_duplicate';
                    break;
                }
            }
        }
        return $errors;
    }

    private static function normalize(?string $date): ?string
    {
        $date = $date === null ? '' : trim($date);
        return $date === '' ? null : $date;
    }
}
