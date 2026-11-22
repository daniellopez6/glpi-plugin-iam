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
 * Who may see a person in the history views (assignments, case search). Pure decision, unit tested.
 *
 * A person with authorisations (Profile_User rows) is visible when one of them is in an active entity (recursion-aware):
 * a person who only has authorisations in entities the session cannot see stays hidden. A leaver whose authorisations
 * were all removed has no entity any more: a session that reads the whole register (ACCESS READ) still sees them when
 * the record that anchors them (an assignment of a visible position, a visible grant) is visible, so the history of
 * leavers stays auditable. Owners (READ_OWNED) never see such people.
 */
final class PersonVisibility
{
    public static function visible(bool $hasAuthorisations, bool $inActiveEntity, bool $readAll, bool $anchorVisible): bool
    {
        if ($hasAuthorisations) {
            return $inActiveEntity;
        }
        return $readAll && $anchorVisible;
    }
}
