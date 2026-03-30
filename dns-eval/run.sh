#!/bin/bash
set -e

mkdir -p Inputs

python3 Mappings/normalize_input.py
python3 Mappings/evaluate.py
