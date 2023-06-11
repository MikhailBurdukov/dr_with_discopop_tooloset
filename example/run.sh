export DP_BUILD=/home/burdukov/workspace/build

echo $@

mkdir _tmp
cp $@ ./_tmp/example.cpp
cd _tmp

$DP_BUILD/scripts/dp-fmap

clang++ -g -c -O0 -S -emit-llvm -fno-discard-value-names example.cpp -o example.ll

opt-11 -S -load=$DP_BUILD/libi/LLVMDiscoPoP.so --DiscoPoP example.ll -o example_dp.ll --fm-path FileMapping.txt

clang++ example_dp.ll -o out_prof -L$DP_BUILD/rtlib -lDiscoPoP_RT -lpthread

./out_prof

discopop_explorer --path=. --dep-file=out_prof_dep.txt >result.txt

cd ..


cp ./_tmp/result.txt ./result_$@.txt
rm -rf _tmp

