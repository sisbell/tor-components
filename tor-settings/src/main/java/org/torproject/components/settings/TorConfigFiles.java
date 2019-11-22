package org.torproject.components.settings;

import java.io.File;
import java.util.Objects;

public final class TorConfigFiles {

    private final File controlPortFile;

    private final File cookieAuthFile;

    private final File geoIpFile;

    private final File geoIpV6File;

    private final File nameserverFile;

    public TorConfigFiles(File controlPortFile, File cookieAuthFile,
                          File geoIpFile, File geoIpV6File, File nameserverFile) {
        this.controlPortFile = controlPortFile;
        this.cookieAuthFile = cookieAuthFile;
        this.geoIpFile = geoIpFile;
        this.geoIpV6File = geoIpV6File;
        this.nameserverFile = nameserverFile;
    }

    public File getControlPortFile() {
        return controlPortFile;
    }

    public File getCookieAuthFile() {
        return cookieAuthFile;
    }

    public File getGeoIpFile() {
        return geoIpFile;
    }

    public File getGeoIpV6File() {
        return geoIpV6File;
    }

    public File getNameserverFile() {
        return nameserverFile;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TorConfigFiles that = (TorConfigFiles) o;
        return Objects.equals(controlPortFile, that.controlPortFile) &&
                Objects.equals(cookieAuthFile, that.cookieAuthFile) &&
                Objects.equals(geoIpFile, that.geoIpFile) &&
                Objects.equals(geoIpV6File, that.geoIpV6File) &&
                Objects.equals(nameserverFile, that.nameserverFile);
    }

    @Override
    public int hashCode() {
        return Objects.hash(controlPortFile, cookieAuthFile, geoIpFile, geoIpV6File, nameserverFile);
    }
}
