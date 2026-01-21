#!/bin/sh

# Load variables
. /opt/etc/radvd/radvd.conf.vars

cat <<EOF
interface ${RADVD_IF} {
    AdvSendAdvert on;

    prefix ${RADVD_PREFIX} {
        AdvOnLink on;
        AdvAutonomous on;
        AdvValidLifetime ${RADVD_VALID_LFT};
        AdvPreferredLifetime ${RADVD_PREF_LFT};
    };

    RDNSS ${RADVD_RDNSS} {
        AdvRDNSSLifetime ${RADVD_RDNSS_LFT};
    };
};
EOF