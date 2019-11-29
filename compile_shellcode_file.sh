#!/bin/bash

gcc $1.c -o $1 -fno-stack-protector -z execstack
