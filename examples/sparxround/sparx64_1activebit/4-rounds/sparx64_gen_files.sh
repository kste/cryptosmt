#!/bin/bash

echo "Generate files"

for index in `seq 0 63`; do
	mv sparx64-1rounds-bit-${index}.yaml sparx64-4rounds-bit-${index}.yaml
done



echo "done."
