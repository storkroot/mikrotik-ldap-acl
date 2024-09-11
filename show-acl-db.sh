#!/usr/bin/env bash

sort ./acl.db | \
    sed '1i\Distinguished Name;ACL;SID' | \
    column -s ";" -t
exit 0
