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
 * Rules of the append-only notes (pure logic, no GLPI): allowed targets and the whitelist of the add input.
 * Author and date always come from the server; the entity is copied from the target by Note.
 */
final class NoteRules
{
    /** Items that can carry notes (1.1+ appends Deviation, Campaign, CampaignItem). Exact class names only. */
    public const TARGETS = [Grant::class, Resource::class, Position_User::class];

    /** Maximum length of a note, in characters. */
    public const MAX_LENGTH = 10000;

    public static function isTarget(mixed $itemtype): bool
    {
        return is_string($itemtype) && in_array($itemtype, self::TARGETS, true);
    }

    /**
     * Trimmed content ('' when missing or not a scalar).
     *
     * @param array<string,mixed> $input
     */
    public static function content(array $input): string
    {
        $content = $input['content'] ?? '';
        return is_scalar($content) ? trim((string) $content) : '';
    }

    /**
     * Error codes of an add input: target_invalid, content_empty, content_too_long.
     *
     * @param array<string,mixed> $input
     * @return list<string>
     */
    public static function errors(array $input): array
    {
        $errors = [];
        $itemsId = $input['items_id'] ?? 0;
        if (!self::isTarget($input['itemtype'] ?? null) || !is_numeric($itemsId) || (int) $itemsId <= 0) {
            $errors[] = 'target_invalid';
        }
        $content = self::content($input);
        if ($content === '') {
            $errors[] = 'content_empty';
        } elseif (mb_strlen($content, 'UTF-8') > self::MAX_LENGTH) {
            $errors[] = 'content_too_long';
        }
        return $errors;
    }

    /**
     * The only fields stored on add, or false when the input is not valid.
     *
     * @param array<string,mixed> $input
     * @return array{itemtype:string,items_id:int,content:string,plugin_iam_notes_id:int,users_id:int,date_creation:string}|false
     */
    public static function prepareAdd(array $input, int $uid, string $now): array|false
    {
        if (self::errors($input) !== []) {
            return false;
        }
        $ref = $input['plugin_iam_notes_id'] ?? 0;
        return [
            'itemtype'            => (string) $input['itemtype'],
            'items_id'            => (int) $input['items_id'],
            'content'             => self::content($input),
            'plugin_iam_notes_id' => is_numeric($ref) ? max(0, (int) $ref) : 0,
            'users_id'            => $uid,
            'date_creation'       => $now,
        ];
    }

    /**
     * Criteria selecting the notes of a target (DBmysqlIterator style, on the notes table): used for the log tab and
     * for the purge guards of targets that can be purged (a target with notes is never purged).
     *
     * @return array{itemtype:string,items_id:int}
     */
    public static function targetCriteria(string $itemtype, int $itemsId): array
    {
        return ['itemtype' => $itemtype, 'items_id' => $itemsId];
    }

    /**
     * A corrected note must belong to the same target as the correction.
     *
     * @param array<string,mixed> $note the referenced note row
     */
    public static function sameTarget(array $note, string $itemtype, int $itemsId): bool
    {
        return (string) ($note['itemtype'] ?? '') === $itemtype && (int) ($note['items_id'] ?? 0) === $itemsId;
    }
}
