#!/bin/bash

base="ou=test,dc=nowhere,dc=net"
adtool="adtool -b $base"

ok="\033[20D\033[25C\033[32;1mOK\033[0m"
broken="\033[20D\033[25C\033[31;1mBROKEN\033[0m"

exec 6>&1
exec 1>/dev/null

# test list and oucreate
$adtool oucreate testou $base
if [ $? -ne 0 ]
then
 echo -e oucreate $broken >&6
 exit
fi
$adtool list $base >tmp.txt
if [ $? -ne 0 ]
then
 echo -e list $broken >&6
 exit
fi
grep testou tmp.txt
if [ $? -ne 0 ]
then
 echo -e list or oucreate $broken >&6
 exit
fi
echo -e list $ok >&6
echo -e oucreate $ok >&6

#test oudelete
$adtool oudelete testou
if [ $? -ne 0 ]
then
 echo -e oudelete $broken
fi
$adtool list $base >tmp.txt
grep testou tmp.txt
if [ $? -eq 0 ]
then
 echo -e oudelete $broken >&6
 exit
fi
echo -e oudelete $ok >&6

#test usercreate
$adtool usercreate testuser $base
if [ $? -ne 0 ]
then
 echo -e usercreate $broken
 exit
fi
$adtool list $base >tmp.txt
grep testuser tmp.txt
if [ $? -ne 0 ]
then
 echo -e usercreate $broken >&6
 exit
fi
echo -e usercreate $ok >&6

#test userdelete
$adtool userdelete testuser
if [ $? -ne 0 ]
then
 echo -e userdelete $broken
 exit
fi
$adtool list $base >tmp.txt
grep testuser tmp.txt
if [ $? -eq 0 ]
then
 echo -e userdelete $broken >&6
 exit
fi
echo -e userdelete $ok >&6

#test attributeget
$adtool usercreate testuser $base
$adtool attributeget testuser name >tmp.txt
$adtool userdelete testuser
grep testuser tmp.txt
if [ $? -ne 0 ]
then
 echo -e attributeget $broken >&6
 exit
fi
echo -e attributeget $ok >&6

#test attributereplace
$adtool usercreate testuser $base
$adtool attributereplace testuser description blah
$adtool attributeget testuser description >tmp.txt
$adtool userdelete testuser
grep blah tmp.txt
if [ $? -ne 0 ]
then
 echo -e attributereplace $broken >&6
 exit
fi
echo -e attributereplace $ok >&6

#test attributeadd
$adtool usercreate testuser $base
$adtool attributeadd testuser othertelephone 123
$adtool attributeadd testuser othertelephone 456
$adtool attributeadd testuser othertelephone 789
$adtool attributeget testuser othertelephone >tmp.txt
$adtool userdelete testuser
grep 456 tmp.txt
if [ $? -ne 0 ]
then
 echo -e attributeadd $broken >&6 
 exit
fi
echo -e attributeadd $ok >&6

#test userunlock
$adtool usercreate testuser $base
$adtool userunlock testuser
$adtool attributeget testuser useraccountcontrol >tmp.txt
$adtool userdelete testuser
grep 66048 tmp.txt
if [ $? -ne 0 ]
then
 echo -e userunlock $broken >&6
 exit
fi
echo -e userunlock $ok >&6

#test userlock
$adtool usercreate testuser $base
$adtool userunlock testuser
$adtool userlock testuser
$adtool attributeget testuser useraccountcontrol >tmp.txt
$adtool userdelete testuser
grep 66050 tmp.txt
if [ $? -ne 0 ]
then
 echo -e userlock $broken >&6
 exit
fi
echo -e userlock $ok >&6

#test setpass
$adtool usercreate testuser $base
$adtool setpass testuser blah
if [ $? -ne 0 ]
then
 echo -e setpass $broken >&6
else
 echo -e setpass $ok >&6
fi
$adtool userdelete testuser

#test usermove
$adtool oucreate testou1 $base
$adtool oucreate testou2 $base
$adtool usercreate testuser ou=testou1,$base
$adtool usermove testuser ou=testou2,$base
$adtool list ou=testou2,$base >tmp.txt
$adtool userdelete testuser
$adtool oudelete testou1
$adtool oudelete testou2
grep testuser tmp.txt
if [ $? -ne 0 ]
then
 echo -e usermove $broken >&6
 exit
fi
echo -e usermove $ok >&6

#test userrename
$adtool usercreate testuser $base
$adtool userrename testuser yoda
$adtool attributeget yoda cn >tmp.txt
$adtool userdelete yoda
grep yoda tmp.txt
if [ $? -ne 0 ]
then
 echo -e userrename $broken >&6
 exit
fi
echo -e userrename $ok >&6

#test search
$adtool oucreate testou $base
$adtool usercreate testuser ou=testou,$base
$adtool attributereplace testuser description muppet
$adtool search description muppet >tmp.txt
$adtool userdelete testuser
$adtool oudelete testou
grep testuser tmp.txt
if [ $? -ne 0 ]
then
 echo -e search $broken >&6
 exit
fi
echo -e search $ok >&6

#test groupcreate/delete
$adtool groupcreate testgroup $base
$adtool search objectclass group >tmp.txt
$adtool groupdelete testgroup
$adtool search objectclass group >tmp2.txt
grep testgroup tmp.txt
if [ $? -ne 0 ]
then
 echo -e groupcreate $broken >&6
 exit
fi
echo -e groupcreate $ok >&6
grep testgroup tmp2.txt
if [ $? -eq 0 ]
then
 echo -e groupdelete $broken >&6
 exit
fi
echo -e groupdelete $ok >&6




