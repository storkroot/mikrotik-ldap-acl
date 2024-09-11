#!/usr/bin/env bash

err=0
force=0
debug=0

. common.env

t1=$(date "+%s")
t2=$(stat -c %Y "$IT_51_IPP")
script=$(basename "$0")

passed_args=$@
if [[ ${#passed_args} -ne 0 ]]; then
  while getopts ":dhfv" option; do
    case $option in
      d) debug=1 ;;
      h) cat "$IT_51_HERE/help/$script.txt" && exit 0 ;;
      f) force=1 ;;
      v) echo "$script: version $(cat $IT_51_HERE/help/version.txt)" && exit 0 ;;
      :) echo "$script: option requires an argument -- $OPTARG" >&2 && exit 1 ;;
      \?) echo "$script: illegal option -- $OPTARG" >&2 && exit 1 ;;
    esac
  done
fi

shift "$((OPTIND-1))"

if host "$IT_51_LDAP_HOST" > /dev/null; then
    if ! nc -z "$IT_51_LDAP_HOST" 389; then
        echo "$script: Error: connect to $IT_51_LDAP_HOST port 389 (tcp) failed: Connection refused" >&2
        exit 1
    fi
else
    echo "$script: Error: host $IT_51_LDAP_HOST not found" >&2
    exit 1
fi

get_list () {
    ldapsearch -D "$IT_51_BIND_DN" -w "$IT_51_BIND_PASS" -P 3 -LLL -b "$IT_51_LDAP_SEARCH_BASE" -H "ldap://$IT_51_LDAP_HOST" \
      "(&(memberOf:1.2.840.113556.1.4.1941:=$1)(objectCategory=person)(objectClass=user))" sAMAccountName 2>/dev/null | grep ^sAMAccountName | \
      cut -d" " -f2
}

add_cmds () {
    while read -r -u9 n; do
        for user in $n ${n}2 ${n}3; do
            ipaddr=$(grep "^$user," "$IT_51_IPP" | cut -d, -f2)
            if [ ! -z "$ipaddr" ]; then
                echo "/ip firewall address-list add address=$ipaddr comment=\"sid=$sid, wcr=$IT_51_MT_USR, user=$user\" list=$acl"
            fi
        done
    done 9< "$IT_51_HERE/var/lib/${1}.0" > "$IT_51_HERE/temp/$acl-$sid.cmds"
}

upd_acl () {
    if ssh -T -i "$IT_51_HERE/keys/$IT_51_MT_USR" "$IT_51_MT_USR"@"$1" "/ip/firewall/address-list/remove [find comment ~\"sid=$3\"]"; then
        if ssh -T -i "$IT_51_HERE/keys/$IT_51_MT_USR" "$IT_51_MT_USR"@"$1" < "$IT_51_HERE/temp/$2-$3.cmds"; then
            echo "$script: The $2 address list on router $1 has been updated successfully!"
            return 0
        else
            echo "$script: Errors occurred while updating the $2 address-list!"
            return 1
        fi
    else
        return 1
    fi
}

find $IT_51_HERE/temp -type f -name "*.cmds" -exec rm -f {} \;

if [ $force -eq 1 ]; then
    rm -f $IT_51_HERE/var/lib/* 2>/dev/null
fi

while IFS=";" read -r -u8 -a i; do
    dn="${i[0]}"
    acl="${i[1]}"
    sid="${i[2]}"

    if [ -f "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).0" ]; then
        mv "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).0" "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).1"
    fi

    get_list "$dn" | sort > "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).0"

    if ! grep "No such object (32)" "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).0" && test -s "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).0"; then
        if [ -f "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).1" ]; then
            if ! diff "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).0" "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).1" > /dev/null || [ $((t1-t2)) -le 900 ]; then
                add_cmds "$(echo "$dn" | cut -d, -f1 | cut -d= -f2)"
                for rtr in $IT_51_MT_RTR; do
                    if ! upd_acl "$rtr" "$acl" "$sid"; then
                        err=$((err+1))
                    fi
                done
            fi
        else
            add_cmds "$(echo "$dn" | cut -d, -f1 | cut -d= -f2)"
            for rtr in $IT_51_MT_RTR; do
                if ! upd_acl "$rtr" "$acl" "$sid"; then
                    err=$((err+1))
                fi
            done
        fi
    else
        err=$((err+1))
        if [ $debug -eq 1 ]; then
            echo "$script: Error: Group $dn does not exist or is empty!"
        fi
        rm "$IT_51_HERE/var/lib/$(echo "$dn" | cut -d, -f1 | cut -d= -f2).0"
    fi
done 8< "$IT_51_HERE/acl.db"

if [ $err -ge 0 ]; then
    exit 1
else
    exit 0
fi
