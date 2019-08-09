#!/bin/bash

echo "Generate files"

for index in `seq 1 63`; do
	touch sparx64-2rounds-bit-${index}.yaml
done



echo "done."
