#!/usr/bin/env bash

# rm -Rf node_modules
# npm install

profile='<my-tenant>-default'

wt ls -p $profile
wt rm password-reset -p $profile
rm -Rf build

npm run bundle
./create.sh $profile

