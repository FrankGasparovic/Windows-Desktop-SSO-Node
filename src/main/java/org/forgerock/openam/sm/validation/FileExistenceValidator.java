/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2020 IC Consult.
 */
package org.forgerock.openam.sm.validation;

import com.sun.identity.sm.ServiceAttributeValidator;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Set;

/**
 * {@link ServiceAttributeValidator} which validates that given set contains Strings which are valid paths to existing files.
 * Also ensure that the Set contains at minimum one value
 */
public class FileExistenceValidator implements ServiceAttributeValidator {

    @Override
    public boolean validate(Set<String> set) {

        if (set == null || set.isEmpty()) {
            return false;
        }

        for (String value : set) {
            if (!Files.exists(Paths.get(value)) || value.isEmpty()) {
                return false;
            }
        }

        return true;
    }
}