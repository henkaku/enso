#!/bin/bash

make_flags="-j 4"

if (( $# < 2 )); then
  echo "$0 git_dir [cid1 cid2 ...]"
  exit 0
else
  git_dir="$1"; shift
  src_dir="`pwd`"
fi

while test $# -gt 0
do
  cid="`echo $1 | tr '[:upper:]' '[:lower:]'`"
  echo "Building for ${cid}"
  mkdir "/tmp/$cid"
  pushd "/tmp/$cid"
  cmake -DPERSONALIZED=1 -DCID="${cid}" "${src_dir}"
  make ${make_flags}
  popd
  mv "/tmp/$cid/fat_installer.vpk" "${git_dir}/dl/${cid}.vpk"
  rm -rf "/tmp/$cid"
  pushd "${git_dir}"
  git add "dl/${cid}.vpk"
  popd
  list="${list}"$'\n'"${cid}"
  shift
done

echo "Committing to git..."
pushd "${git_dir}"
git commit -m "Added new personalized builds for: ${list}"
git push
echo "Done."
