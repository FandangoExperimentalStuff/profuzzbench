Please carefully read the [main README.md](../../../README.md), which is stored in the benchmark's root folder, before following this subject-specific guideline.

# Fuzzing Dcmtk server with AFLNet
Please follow the steps below to run and collect experimental results for Dcmtk, which is a lightweight DICOM server.

## Step-1. Build a docker image
The following commands create a docker image tagged dcmtk. The image should have everything available for fuzzing and code coverage calculation.

```bash
cd $PFBENCH
cd subjects/DICOM/Dcmtk
docker build . -t dcmtk
```

## Step-2. Run fuzzing
The following commands run 4 instances of AFLNet to fuzz Dcmtk in 60 minutes.

```bash
cd $PFBENCH
mkdir results-dcmtk

profuzzbench_exec_common.sh dcmtk 4 results-dcmtk aflnet out-dcmtk-aflnet "-P DICOM -D 10000 -E -K" 3600 5
```

## Step-3. Collect the results
The following commands collect the  code coverage results produced by AFLNet and save them to results.csv.

```bash
cd $PFBENCH/results-dcmtk

profuzzbench_generate_csv.sh dcmtk 4 aflnet results.csv 0
```

## Step-4. Analyze the results
The results collected in step 3 (i.e., results.csv) can be used for plotting. Use the following command to plot the coverage over time and save it to a file.

```
cd $PFBENCH/results-dcmtk

profuzzbench_plot.py -i results.csv -p dcmtk -r 4 -c 60 -s 1 -o cov_over_time.png
```
