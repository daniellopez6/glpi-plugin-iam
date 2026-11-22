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

use CommonGLPI;

/**
 * Entry that defines the top-level "Access governance (IAM)" menu. Visible only with some IAM right.
 */
class Menu extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return __('Access governance (IAM)', 'iam');
    }

    public static function getMenuName()
    {
        return __('Access governance (IAM)', 'iam');
    }

    public static function getIcon(): string
    {
        return 'ti ti-key';
    }

    public static function getSearchURL($full = true)
    {
        // The matrix is the landing page of the sector: every IAM profile that may open the menu may open it
        return plugin_iam_url('front/matrix.php', $full);
    }

    public static function getMenuContent()
    {
        if (!Rights::hasAny()) {
            return false;
        }
        $options = [];
        if (Matrix::canView()) {
            $options['matrix'] = [
                'title' => __('Access matrix', 'iam'),
                'page'  => self::getSearchURL(false),
                'icon'  => 'ti ti-table',
            ];
        }
        if (Matrix::canView()) {
            $options['search'] = [
                'title' => __('Case search', 'iam'),
                'page'  => plugin_iam_url('front/search.php', false),
                'icon'  => 'ti ti-search',
            ];
        }
        if (Position::canView()) {
            $options[Position::class] = [
                'title' => Position::getTypeName(2),
                'page'  => Position::getSearchURL(false),
                'icon'  => Position::getIcon(),
                'links' => ['search' => Position::getSearchURL(false)]
                    + (Position::canCreate() ? ['add' => Position::getFormURL(false)] : []),
            ];
        }
        if (Resource::canView()) {
            $options[Resource::class] = [
                'title' => Resource::getTypeName(2),
                'page'  => Resource::getSearchURL(false),
                'icon'  => Resource::getIcon(),
                'links' => ['search' => Resource::getSearchURL(false)]
                    + (Resource::canCreate() ? ['add' => Resource::getFormURL(false)] : []),
            ];
        }
        if (Grant::canView()) {
            $options[Grant::class] = [
                'title' => Grant::getTypeName(2),
                'page'  => Grant::getSearchURL(false),
                'icon'  => Grant::getIcon(),
                'links' => ['search' => Grant::getSearchURL(false)]
                    + (Grant::canCreate() ? ['add' => Grant::getFormURL(false)] : []),
            ];
        }
        $options['help'] = [
            'title' => Help::getTypeName(),
            'page'  => Help::getSearchURL(false),
            'icon'  => Help::getIcon(),
        ];
        // Landing page: the first entry the profile can open (the matrix for every IAM profile but a REPORT-only one)
        $first = reset($options);
        return [
            'title'   => self::getMenuName(),
            'page'    => $first !== false ? $first['page'] : self::getSearchURL(false),
            'icon'    => self::getIcon(),
            'options' => $options,
        ];
    }
}
