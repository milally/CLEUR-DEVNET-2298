#!/bin/bash
while read IP UNAME PASSWD
do
  MYCOOKIE=$(curl -s -k -d "<aaaLogin inName=\"$UNAME\" inPassword=\"$PASSWD\"></aaaLogin>" $IP | xmllint --xpath "string(//aaaLogin/@outCookie)" -)
  SCHSTATE=$(curl -s -k -H "Content-Type: text/xml" -N -s -d "<configResolveClass classId="callhomeEp" cookie=\"$MYCOOKIE\" inHierarchical="false" />;" $IP | xmllint --xpath "string(//callhomeEp/@adminState)" -)
  SNMPSTATE=$(curl -s -k -H "Content-Type: text/xml" -N -s -d "<configResolveClass classId="commSnmp" cookie=\"$MYCOOKIE\" inHierarchical="false" />;" $IP | xmllint --xpath "string(//commSnmp/@adminState)" -)
  echo $IP" - SmartCallHome State: "$SCHSTATE" SNMP State: "$SNMPSTATE
  curl -s -k -d "<aaaLogout inCookie=\"$MYCOOKIE\" ></aaaLogout>" $IP > /dev/null
done < servers.txt