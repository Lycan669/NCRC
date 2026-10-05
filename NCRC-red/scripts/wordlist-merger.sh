#!/bin/bash
# Merge all wordlists into one super list

cat wordlists/*.txt | sort | uniq > wordlists/all-combined.txt
echo "✅ Wordlist fusionné: wordlists/all-combined.txt"
echo "📊 Total d'entrées: $(wc -l < wordlists/all-combined.txt)"