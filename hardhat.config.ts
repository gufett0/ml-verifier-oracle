import { HardhatUserConfig } from "hardhat/config"
import "@nomicfoundation/hardhat-toolbox"
import "hardhat-gas-reporter"
import "@nomicfoundation/hardhat-chai-matchers"
import "@nomicfoundation/hardhat-ethers";
import dotenv from 'dotenv';
dotenv.config();

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.20',
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  gasReporter: {
    enabled: (process.env.REPORT_GAS === 'true'),
    currency: 'USD',
    gasPrice: 21,
  },
};

export default config;