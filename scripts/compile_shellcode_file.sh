#!/bin/bash

gcc $1.c -o $1 -m32 -fno-stack-protector -z execstack
