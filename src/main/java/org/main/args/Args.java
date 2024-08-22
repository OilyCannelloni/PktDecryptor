package org.example.args;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.util.List;

@Parameters(parametersValidators = ArgsValidator.class)
public class Args {
    @Parameter(names = {"-d", "--decrypt"}, description = "Decrypt a .pkt file into an XML")
    public boolean decrypt;

    @Parameter(names = {"-e", "--encrypt"}, description = "Encrypt an XML into a .pkt file")
    public boolean encrypt;

    @Parameter(names = {"-v", "--verbose"}, description = "Print hexdumps from all stages of the process")
    public boolean verbose;

    @Parameter(description = "input-file output-file", arity = 2, required = true)
    public List<String> files;

    @Parameter(names = "--help", help = true)
    public boolean help;
}
