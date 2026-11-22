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
use Glpi\Application\View\TemplateRenderer;
use Profile as GlpiProfile;
use ProfileRight;

/**
 * "Access governance (IAM)" tab on the profile form: rights matrix, plus creation of the role profiles.
 */
class Profile extends CommonGLPI
{
    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (
            $item instanceof GlpiProfile && !$item->isNewItem() && ($item->fields['interface'] ?? '') === 'central'
            && GlpiProfile::canView()
        ) {
            return self::createTabEntry(__('Access governance (IAM)', 'iam'), 0, null, 'ti ti-key');
        }
        return '';
    }

    /**
     * Rights matrix. Labels are identical on every row so that GLPI groups each right in a single column.
     * No itemtype is given (the rights are listed explicitly), so no class has to exist for a row.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getRightsMatrix(): array
    {
        $read      = ['short' => __('See all', 'iam'), 'long' => __('See all items', 'iam')];
        $readOwn   = ['short' => __('See own', 'iam'), 'long' => __('See only the accesses of own resources', 'iam')];
        $update    = ['short' => __('Update', 'iam'), 'long' => __('Update the items the user can see', 'iam')];
        $updateOwn = ['short' => __('Update own', 'iam'), 'long' => __('Update only the accesses of own resources', 'iam')];
        $create    = ['short' => __('Create', 'iam'), 'long' => __('Create items', 'iam')];
        $trash     = ['short' => __('Put in trashbin', 'iam'), 'long' => __('Put in trashbin', 'iam')];
        $purge     = ['short' => __('Purge', 'iam'), 'long' => __('Delete permanently', 'iam')];
        return [
            [
                'label'  => __('Access register (grants, deviations and notes)', 'iam'),
                'field'  => Rights::ACCESS,
                'rights' => [READ => $read, READ_OWNED => $readOwn, UPDATE => $update, UPDATE_OWNED => $updateOwn, CREATE => $create],
            ],
            [
                'label'  => __('Catalogue (positions, resources, roles, access matrix and SoD rules)', 'iam'),
                'field'  => Rights::CONFIG,
                'rights' => [READ => $read, UPDATE => $update, CREATE => $create, DELETE => $trash, PURGE => $purge],
            ],
            [
                'label'  => __('Recertification reviews', 'iam'),
                'field'  => Rights::REVIEW,
                'rights' => [UPDATE => ['short' => __('Review accesses', 'iam'), 'long' => __('Confirm or revoke accesses in recertification campaigns', 'iam')]],
            ],
            [
                'label'  => __('Approvals (requests and deviations)', 'iam'),
                'field'  => Rights::APPROVE,
                'rights' => [UPDATE => ['short' => __('Approve', 'iam'), 'long' => __('Approve or reject requests and deviations (never own ones)', 'iam')]],
            ],
            [
                'label'  => __('Reports and exports', 'iam'),
                'field'  => Rights::REPORT,
                'rights' => [READ => ['short' => __('See reports', 'iam'), 'long' => __('See and export reports', 'iam')]],
            ],
        ];
    }

    /**
     * Creates the missing role profiles (matched by the [iam:key] marker in the comment), never modifying
     * existing ones.
     *
     * @return list<string> names of the created profiles
     */
    public static function createRoleProfiles(): array
    {
        $created = [];
        foreach (Rights::roleProfiles() as $key => $def) {
            $marker = Rights::marker($key);
            if (countElementsInTable(GlpiProfile::getTable(), ['comment' => ['LIKE', '%' . $marker . '%']]) > 0) {
                continue;
            }
            $profile = new GlpiProfile();
            $id = $profile->add([
                'name'      => $def['name'],
                'interface' => 'central',
                'comment'   => $def['comment'],
            ]);
            if ($id) {
                ProfileRight::updateProfileRights((int) $id, $def['rights']);
                $created[] = $def['name'];
            }
        }
        return $created;
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        TemplateRenderer::getInstance()->display('@iam/profile_rights.html.twig', [
            'item'   => $item,
            'rights' => self::getRightsMatrix(),
        ]);
        return true;
    }
}
