# phiward: the names of the variables its hooks clear (install.CLEARED_PREFIXES and
# install.CLEARED_NAMES, and a TZ that names a file), on one line
BEGIN {
    for (k in ENVIRON)
        if (k ~ /^(PYTHON|LD_|DYLD_|OPENSSL_|MALLOC_|Malloc)[A-Za-z0-9_]*$/ ||
            k ~ /^(__PYVENV_LAUNCHER__|GCONV_PATH|LOCPATH|NLSPATH|GLIBC_TUNABLES|HOSTALIASES|LOCALDOMAIN|RES_OPTIONS|RESOLV_HOST_CONF|NIS_PATH|TZDIR|GETCONF_DIR)$/ ||
            (k == "TZ" && (ENVIRON[k] ~ /^:?\// || ENVIRON[k] ~ /\.\./)))
            printf "%s ", k
}
