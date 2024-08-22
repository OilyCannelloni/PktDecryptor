package org.example.args;

import com.beust.jcommander.IParametersValidator;
import com.beust.jcommander.ParameterException;

import java.util.Map;

import static java.lang.Boolean.TRUE;

public class ArgsValidator implements IParametersValidator {
    @Override
    public void validate(Map<String, Object> map) throws ParameterException {
        if (map.get("--decrypt") == TRUE && map.get("--encrypt") == TRUE)
            throw new ParameterException("cannot use --decrypt and --encrypt at the same time");
    }
}
