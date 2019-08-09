#!/bin/bash

echo "Generate files"

for index in `seq 1 63`; do
	touch sparx64-3rounds-bit-${index}.yaml
done



echo "done."
