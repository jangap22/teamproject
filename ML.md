# ML Pipeline Requirements Specification

## 1. Purpose

This document defines the requirements and constraints for the machine learning
pipeline used by the DNS cache poisoning IDS project. The ML pipeline runs on
the user's Mac, while packet capture and real-time detection run on an Ubuntu
server.

The ML implementation must produce RandomForest model artifacts that remain
compatible with the existing sniffer detector without changing the live
detection flow.

## 2. System Boundary

### Existing Ubuntu runtime

The Ubuntu environment already owns the following responsibilities:

- `resolver` starts a session pcap capture when the resolver container starts.
- Capture stops when the resolver container stops.
- Captured files are written as:

```text
data/captures/dataset_v000001.pcap
data/captures/dataset_v000002.pcap
```

- The pcap contains only DNS responses addressed to `RESOLVER_IP` on monitored
  ports `10053`, `20053`, `30053`, and `1025`.
- `sniffer` performs live detection and loads the highest numbered model file
  found under `/models`:

```text
randomforest_v000001.joblib
randomforest_v000002.joblib
```

### New Mac ML pipeline

The ML developer must implement a Mac-local pipeline that:

1. Retrieves versioned pcap datasets from the Ubuntu server.
2. Converts retrieved pcaps to training feature data using the existing sniffer
   feature contract.
3. Labels and versions datasets for supervised learning.
4. Trains and tunes a RandomForest model only.
5. Records metrics and training metadata automatically.
6. Versions notebooks, datasets, metrics, and model artifacts together using
   DVC.
7. Sends an approved versioned `.joblib` artifact back to Ubuntu for use by
   the sniffer.

## 3. Non-Negotiable Constraints

### 3.1 Feature compatibility

The ML pipeline must use the same feature definitions as the existing live
detector:

- Feature extraction reference:
  `scenario/sniffer/features.py`
- Feature schema reference:
  `scenario/sniffer/schema.py`
- Runtime model loading reference:
  `scenario/sniffer/detector.py`

The training pipeline must not invent, rename, remove, reorder, or calculate
features differently from the live sniffer unless a coordinated runtime schema
change is explicitly approved.

Training input features must be derived from `FEATURE_COLUMNS` in
`scenario/sniffer/schema.py`. Metadata and label fields are not predictive
features unless an explicit approved schema change states otherwise.

The following metadata fields must not leak into model fitting:

```text
packet_index
timestamp
src_ip
dst_ip
qname
answer_ips
label
attack_type
scenario_tag
```

### 3.2 Algorithm restriction

The only permitted classifier is RandomForest.

- Permitted: `sklearn.ensemble.RandomForestClassifier`
- Permitted: preprocessing within an sklearn `Pipeline`, for example encoding
  the existing `transport` categorical feature.
- Not permitted without separate approval: XGBoost, LightGBM, neural networks,
  SVM, logistic regression, voting/stacking ensembles, or replacement
  classifiers.

### 3.3 Existing runtime preservation

The ML implementation must not alter the live Ubuntu capture or IDS behavior as
part of routine model training.

- Do not train models inside Ubuntu runtime containers.
- Do not train while the Ubuntu experiment is expected to be running.
- Do not overwrite or rename existing pcaps on Ubuntu.
- Do not automatically deploy a model immediately after training without an
  explicit user deployment action.
- Do not require changes to current alerting, listener, packet filter, or
  resolver behavior for the ML pipeline to operate.

## 4. Data Contract

### 4.1 Raw dataset source

Raw training evidence originates on Ubuntu as versioned pcap files:

```text
data/captures/dataset_vNNNNNN.pcap
```

Each pcap corresponds to one resolver execution session. The version number is
immutable once a file has been created.

### 4.2 Capture scope

The Mac processing pipeline must accept only packet records matching the
Ubuntu/sniffer capture contract:

```text
DNS response (qr = 1)
AND destination IP equals resolver IP
AND source or destination port is one of:
    10053, 20053, 30053, 1025
```

The conversion step must validate this condition even if the pcap was already
filtered on Ubuntu.

### 4.3 Labels

RandomForest training is supervised; every processed training row must have a
label.

- `label=0`: normal DNS upstream response
- `label=1`: cache poisoning or forged DNS response

Until a time-window annotation design is separately approved, the expected
collection policy is one experiment category per pcap session: normal-only
captures and attack captures are recorded separately.

Each processed row must preserve traceability metadata:

```text
source_pcap_version
label
attack_type
scenario_tag
```

The developer must expose label and scenario metadata as CLI inputs or a
manifest file. They must not infer ground truth silently from predictions.

### 4.4 Processed feature dataset

The conversion pipeline must output versioned feature datasets derived from
pcap inputs, for example:

```text
ml/data/processed/features_v000001.csv
```

The dataset must contain the existing `CSV_COLUMNS` contract or an explicitly
documented superset containing provenance fields. Its model fitting subset must
remain exactly compatible with `FEATURE_COLUMNS`.

## 5. Versioning And DVC Requirements

### 5.1 Version identity

A dataset/model release uses one shared numeric version identifier:

```text
dataset_v000001.pcap
features_v000001.csv
randomforest_v000001.joblib
metrics_v000001.json
train_v000001.executed.ipynb
```

Where more than one raw pcap is required for one trained model, the pipeline
must create a versioned manifest listing all source pcaps and labels rather
than implying one-to-one lineage.

Example:

```text
ml/data/manifests/dataset_v000003.yaml
models/randomforest_v000003.joblib
```

### 5.2 DVC scope

The following must be tracked as one reproducible DVC pipeline or experiment
lineage:

- Raw pcap input files or their versioned dataset manifest
- Processed feature dataset
- Training notebook source
- Executed notebook output
- Hyperparameter configuration
- Metrics and evaluation reports
- Produced `.joblib` model

Git should track lightweight pipeline definitions, source code, `.dvc`/DVC
metadata, notebook source, and small configuration files. DVC should track
large/raw/generated data and trained artifacts.

### 5.3 Reproducibility

Every model version must be reproducible from tracked inputs and configuration.
Each run must record at least:

```text
dataset_version
source_pcap_files
label mapping
feature schema reference or checksum
random seed
train/test split strategy
hyperparameters searched
selected hyperparameters
model output filename
execution timestamp
```

## 6. Training Notebook And CLI Requirements

### 6.1 Notebook

The developer must create a training notebook that performs the model training
and evaluation workflow. The notebook must be parameterizable and automatically
executable from a CLI command; manual cell execution alone is not acceptable.

Expected artifacts:

```text
ml/notebooks/train_randomforest.ipynb
ml/runs/train_vNNNNNN.executed.ipynb
```

### 6.2 CLI

The Mac pipeline must provide command-line entry points for at least:

```text
fetch-data      Retrieve pcap files from Ubuntu
build-dataset   Convert and label pcaps into feature datasets
train           Execute the notebook and generate metrics/model artifacts
deploy-model    Send a selected joblib model to Ubuntu
```

The CLI must accept Ubuntu connection values at runtime or via a local ignored
configuration file. Ubuntu host IP, username, key/password, and remote path
must not be committed or hardcoded because the user will provide them later.

### 6.3 Hyperparameter tuning

Training must support configurable RandomForest hyperparameter tuning. At a
minimum, the implementation must allow search over:

```text
n_estimators
max_depth
min_samples_split
min_samples_leaf
max_features
class_weight
```

The search approach may be `GridSearchCV` or `RandomizedSearchCV`, but it must
be configurable, reproducible through a fixed random seed where applicable,
and record the candidate space and selected parameters.

## 7. Model Artifact Contract

The produced `.joblib` file must be readable by the existing
`ModelDetector.load_model()` implementation. It must contain:

```python
{
    "model": trained_sklearn_pipeline,
    "feature_columns": list_of_columns_used_for_training,
    "best_params": selected_hyperparameters,
}
```

Additional metadata may be added to this dictionary, including:

```python
{
    "dataset_version": "v000001",
    "metrics": {...},
    "feature_schema_checksum": "...",
    "training_timestamp": "...",
}
```

The required keys and feature compatibility must remain intact.

Deployment filename format:

```text
randomforest_vNNNNNN.joblib
```

The Ubuntu sniffer selects the highest numeric version at startup. Deployment
must therefore require explicit user confirmation because uploading a higher
version causes it to become active after sniffer restart.

## 8. Metrics And Evaluation Requirements

### 8.1 Required metrics

Every training run must automatically record at least:

```text
accuracy
precision
recall
f1_score
false_positive_rate
false_negative_rate
roc_auc, when probabilities and both test classes are available
confusion_matrix: TN, FP, FN, TP
train_row_count
test_row_count
class_distribution_train
class_distribution_test
```

### 8.2 Metrics artifacts

Metrics must be stored in machine-readable formats suitable for later
comparison across model versions.

Required:

```text
ml/metrics/metrics_vNNNNNN.json
ml/metrics/metrics_summary.csv
ml/reports/confusion_matrix_vNNNNNN.csv
```

The summary CSV must append one row per trained model version and include
dataset version, model version, selected hyperparameters reference, and all
scalar performance metrics.

### 8.3 Evaluation integrity

The implementation must document and apply a split strategy that avoids
inflated scores caused by highly similar packets from the same capture session
appearing in both training and test data.

Preferred approach:

- Split by capture session or `scenario_tag`, not random packet rows, once
  multiple sessions per class exist.

If a temporary row-level stratified split is used during bootstrap development,
the resulting metrics must be clearly marked as provisional.

## 9. Ubuntu Transfer Requirements

### 9.1 Dataset retrieval

The Mac pipeline must implement retrieval of Ubuntu pcap files from the remote
capture directory:

```text
data/captures/dataset_vNNNNNN.pcap
```

The implementation must:

- Support user-supplied Ubuntu host/IP and SSH credentials later.
- Download without overwriting an existing local version unless explicitly
  requested.
- Verify successful transfer before registering data in the local DVC workflow.
- Preserve the original Ubuntu raw pcap by default.

### 9.2 Model deployment

The Mac pipeline must implement upload of a selected trained model to Ubuntu's
mounted model directory using the versioned filename:

```text
models/randomforest_vNNNNNN.joblib
```

The implementation must:

- Require an explicit selected model version.
- Never silently deploy the latest local experiment.
- Never overwrite an existing remote artifact unless the user explicitly
  authorizes replacement.
- Tell the user that the sniffer must be restarted for the newly uploaded
  highest version model to be selected.

## 10. Deliverables

The ML developer is expected to provide:

1. A Mac-local CLI for data retrieval, dataset build, notebook execution, and
   controlled model deployment.
2. Pcap-to-feature conversion reusing the existing sniffer feature/schema
   contract.
3. A parameterized RandomForest training notebook.
4. Hyperparameter tuning configuration and execution support.
5. DVC pipeline/experiment configuration covering datasets, notebook run,
   metrics, and joblib artifacts.
6. Automated metrics JSON, summary CSV, and confusion matrix outputs.
7. Documentation with commands, configuration placeholders, dataset labeling
   policy, and model deployment procedure.
8. Tests for feature compatibility, version parsing, artifact compatibility,
   and non-overwriting transfer behavior.

## 11. Acceptance Criteria

Implementation is accepted only when all of the following are demonstrated:

- A captured Ubuntu pcap can be fetched to Mac without hardcoded host details.
- The pcap can be converted into labeled feature data matching the existing
  detector feature schema.
- A RandomForest-only notebook training run can be triggered from the CLI.
- Hyperparameter tuning outputs the selected parameters.
- A versioned `.joblib` artifact is produced and loadable by the existing
  sniffer detector contract.
- Notebook, input dataset lineage, generated metrics, and model artifact are
  managed under the same DVC-traceable run/version.
- Performance metrics are stored in comparable machine-readable form.
- A user-selected versioned model can be safely uploaded to Ubuntu.
- No ML action changes the running Ubuntu detection pipeline without an
  explicit deployment and restart action.

## 12. Open Configuration Inputs

The following values must remain configurable and will be supplied by the user
later:

```text
Ubuntu host IP or hostname
Ubuntu SSH username and authentication method
Ubuntu remote project/data/models paths
Mac local ML workspace paths, if different from project defaults
DVC remote backend and credentials
Label/scenario manifest policy for collected sessions
Approved model deployment version
```
