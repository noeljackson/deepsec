package com.example.files;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileService {

    public byte[] readVulnerableFile(String name) throws Exception {
        File f = new File(name);
        return Files.readAllBytes(f.toPath());
    }

    public byte[] readVulnerablePaths(String path) throws Exception {
        return Files.read(Paths.get(path));
    }

    public byte[] readSafeWhitelisted(String slug) throws Exception {
        File base = new File("/var/data");
        File target = new File(base, slug + ".bin").getCanonicalFile();
        if (!target.toPath().startsWith(base.toPath())) {
            throw new SecurityException("outside base");
        }
        return Files.readAllBytes(target.toPath());
    }
}
