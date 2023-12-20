import { ethers as HH } from 'hardhat';
import { expect } from 'chai';
import { Contract } from 'ethers';
import * as dotenv from 'dotenv';
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import data from '../instances2.json';


// Load environment variables from .env file
dotenv.config();
describe('CarbonCreditsContract', function () {
  let creditsAttestation: Contract;
  var addr1: SignerWithAddress; // 

  var validProof = process.env.PROOF1;
  console.log(validProof);
  var invalidProof = process.env.PROOF2;
  console.log(invalidProof);
  var instances = data;
  console.log(instances);

  //var validProof = HH.utils.arrayify(validProof);


  beforeEach(async function () {
    // Deploy Verifier contract
    const Verifier = await HH.getContractFactory('Halo2Verifier');
    const verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // Deploy CreditsAttestation contract
    const CreditsAttestation = await HH.getContractFactory('CarbonCreditsContract');
    creditsAttestation = await CreditsAttestation.deploy(verifier) as unknown as Contract;
    await creditsAttestation.waitForDeployment();

    const signers = await HH.getSigners(); // get the signer for addr1
    addr1 = signers[0];
  });

  it('should deploy the contract with initial state', async function () {
    // Check if the contract is deployed
    console.log("SC address: ", await creditsAttestation.getAddress());
    expect(creditsAttestation.getAddress()).to.not.equal(undefined);

    // Check if the balance of addr1 is initially 0
    console.log("addr1 address: ", addr1.address);
    console.log("addr1 balance: ", await creditsAttestation.balances(addr1.address));
    const initialBalance = await creditsAttestation.balances(addr1.address);
    expect(initialBalance).to.equal(0);
  });


});