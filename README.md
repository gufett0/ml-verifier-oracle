
# README

## Key Features
This repository contains:

* Creation of Siamese neural network models and training.  
* Code to setup, create proofs and verifiy proofs locally.
* Code to deploy verifier and verify proof on-chain.

## Requirements

**A. Hardware Requirements**

The successful deployment and execution of the artifact necessitate the following hardware specifications:

All computations were performed on Python 3 Google Compute Engine backend, with Colab Premium version.

+ **Processor**: 2 Intel(R) Xeon(R) CPU @ 2.20GHz

+ **Memory**: 51GB RAM

+ **Storage**: 20GB free space

**B. Software Requirements**

To ensure a seamless experience with the artifact, the following software components must be installed on the reviewer's system:

+ **Operating System**: macOS >=12.7, or Ubuntu >= 18.04

+ **Programming Language**: Python 3.8+

+ **Additional Dependencies**: Ezkl 7.1.12; Onnx 1.15.0; Solc 0.8.20; the rest of needed libraries are inside Google backend.

If you are using your local machine follow this installations list:

+ Python 3.10
+ Extensions for Solidity (Hardhat), Python, and Jupyter in VSCode
+ npm
+ Node.js (latest LTS version, use command: `sudo n lts`; to check version, use command: `node --version`)

+ Hardhat (install with command: `npm install --save-dev hardhat`)

+ pip

+ ezkl

+ onnx

+ pandas

+ torch

+ torchvision


* solc, for Ubuntu:
  - `sudo add-apt-repository ppa:ethereum/ethereum`
  - `sudo apt-get update`
  - `sudo apt-get install solc`
 
+ `npm install hardhat-gas-reporter --save-dev`

+ (Optional) `npm install dotenv`

## How To Use

**A. Off-Chain Task (EZKL Circuit Setup and Proof Generation)**

**1. Obtaining the Artifact**

+ Download: https://github.com/gufett0/ml-verifier-oracle

**2. Deployment Instructions**

On your local machine navigate inside the _~/prover_ folder and open the Jupiter notebook _halo2circuit.ipynb_. Start by importing all the necessary libraries. Follow the instructions in each separate cell. Once you decide which model you want to setup the circuit for, you can load it along with its trained parameters:

```
loaded_model = FurtherAdjustedSiameseBambooNN().to(device)
loaded_model.load_state_dict(torch.load('../training/trained_simplesnn_lr_0.01S.pth', map_location=torch.device('cpu')))
```

For example, in the above code the smaller model is getting loaded, as indicated by the final character “S” (the big model file would be specified with a “B”).

**3. Execution Steps**

All the execution steps are self-explanatory by reading each cell comments.  
However, there are two main things to keep in mind:  
In the calibration process, after defining the parameters that determine, among other things, the circuit shape and size, 
```shell
res = ezkl.calibrate_settings(cal_path, model_path, settings_path, "resources", max_logrows=18, scales=[1])
```
This will change the settings of the circuit, optimizing more for resources vs. accuracy, as explained in the paper. The 2 configurations described in the published paper, used for both models, are the following:

+ Optimized for for resources:
```shell
res = ezkl.calibrate_settings(cal_path, model_path, settings_path, "resources", max_logrows=18, scales=[1])
```
+ Optimized for accuracy:
```shell
res = ezkl.calibrate_settings(cal_path, model_path, settings_path, "accuracy", max_logrows=18, scales=[6])
```
In cell 19 the output of _ezkl.create_evm_verifier_ is a smart contract file that will overwrite the previous one.  

**B. On-Chain Task (Verification and Validation)**

**2. Deployment and Execution Instructions**

In the root folder of the project, use the following command  
```
npx hardhat test
```

This will execute the hardhat test on the verifier contract and log the corresponding on-chain event of the verification method. Additionally, 
```
REPORT_GAS=true npx hardhat test 
```
will log the gas usage of on-chain operations. If you want to obtain an up-to-date estimate from CoinMarketCap in ETH, MATIC and USD of the gas spent, you can add an .env file to the project root and enter your API key as follows COINMARKETCAP_API_KEY="" and uncomment the line of code inside hardhat.config.ts "//coinmarketcap:process.env.COINMARKETCAP_API_KEY,".

Here are reported some of the commands that can be executed within hardhat
```
npx  hardhat  help
npx  hardhat  test
REPORT_GAS=true  npx  hardhat  test
npx  hardhat  node
npx  hardhat  run  scripts/deploy.ts
```


## Useful links

Link to the paper: not yet available
