FROM cgr.dev/chainguard/static:latest

ARG TARGETPLATFORM

COPY $TARGETPLATFORM/tpmtb /tpmtb

ENTRYPOINT ["/tpmtb"]
