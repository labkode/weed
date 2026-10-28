# Real WLCG clients and a reference HTTP-TPC server (XRootD) for interoperability tests
FROM almalinux:9
RUN dnf install -y epel-release && \
    dnf install -y --setopt=install_weak_deps=False \
        gfal2-util-scripts gfal2-plugin-http gfal2-plugin-file davix \
        xrootd-server xrootd-client openssl procps-ng jq diffutils && \
    dnf clean all
