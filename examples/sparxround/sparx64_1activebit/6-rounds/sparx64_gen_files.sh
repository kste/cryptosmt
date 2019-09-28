#!/bin/bash

echo "Generate files"

for index in `seq 1 63`; do
	mv sparx64-3rounds-bit-${index}.yaml sparx64-6rounds-bit-${index}.yaml
done



echo "done."
