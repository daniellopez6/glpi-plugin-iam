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
 * Input hygiene shared by the plugin items (pure logic): only known fields get in, and immutable ones never change
 * after creation.
 */
final class InputGuard
{
    /**
     * @param array<string,mixed> $input
     * @param list<string>        $allowed   keys that may be present
     * @param list<string>        $immutable keys dropped on update (kept on add)
     *
     * @return array<string,mixed>
     */
    public static function filter(array $input, array $allowed, array $immutable, bool $isUpdate): array
    {
        $keep = $isUpdate ? array_diff($allowed, $immutable) : $allowed;

        return array_intersect_key($input, array_flip($keep));
    }

    /**
     * @param list<string> $choices
     */
    public static function enum(string $value, array $choices): bool
    {
        return in_array($value, $choices, true);
    }
}
