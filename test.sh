test_lpcli () {
local OPTS=$1
local PASS=$2
local EXPECT=$3
local CMDLINE="echo $PASS | ./lpcli $OPTS -p | tail -n1"
echo Test: $CMDLINE
local GENERATED=$(eval $CMDLINE)
if [ "$GENERATED" = $EXPECT ]; then
  echo "PASS"
else
  echo "FAIL"
fi
}

test_lpcli "example.org contact@example.org -ludsc1n16" "password"  "WHLpUL)e00[iHR+w"
test_lpcli "example.org contact@example.org -ludc2n14" "password"  "MBAsB7b1Prt8Sl"
test_lpcli "example.org contact@example.org -dc1n16" "password"  "8742368585200667"
test_lpcli "example.org contact@example.org -lusc1n16" "password"  "s>{F}RwkN/-fmM.X"
test_lpcli "site login -ludsc10n16" "test"  "XFt0F*,r619:+}[."
