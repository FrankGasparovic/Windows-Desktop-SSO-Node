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
            if (!Files.exists(Paths.get(value))) {
                return false;
            }
        }

        return true;
    }
}