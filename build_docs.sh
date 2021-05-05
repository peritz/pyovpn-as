#!/bin/bash

docker run --rm -v $PWD/pyovpn_as:/code/pyovpn_as -v $PWD/docs:/docs sphinxdoc/sphinx sphinx-apidoc -o /docs /

docker run --rm -v $PWD/pyovpn_as:/code/pyovpn_as -v $PWD/docs:/docs sphinxdoc/sphinx make html