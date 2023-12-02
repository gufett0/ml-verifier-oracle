import { ethers as HH } from 'hardhat';
import { expect } from 'chai';
import { Contract } from 'ethers';
import * as dotenv from 'dotenv';
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import data from '../instances2.json';


// Load environment variables from .env file
dotenv.config();
describe('CarbonCreditsContract', function () {
  var verifier: Contract;
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
    //await verifier.deployed();

    // Deploy CreditsAttestation contract
    const CreditsAttestation = await HH.getContractFactory('CarbonCreditsContract');
    creditsAttestation = await CreditsAttestation.deploy(verifier) as unknown as Contract;
    //await creditsAttestation.deployed();

    const signers = await HH.getSigners(); // get the signer for addr1
    addr1 = signers[0];
  });

  it('should allow user to claim credit after a valid proof is submitted', async function () {
    // Submit a valid proof
    const tx = await creditsAttestation.claimCredits(validProof, instances);
    console.log(tx);
    const receipt = await tx.wait();
    console.log('Gas used:', receipt.gasUsed.toString());

    // Check if user balance has increased
    const balance = await creditsAttestation.balances(addr1.address);
    expect(balance).to.be.above(0);
  });

  it('should not allow user to claim credit after an invalid proof is submitted', async function () {
    // Submit an invalid proof
    const tx = await creditsAttestation.claimCredits(invalidProof, instances);
    const receipt = await tx.wait();
    console.log('Gas used:', receipt.gasUsed.toString());
    // Check if user balance has not increased
    const balance = await creditsAttestation.balances(addr1.address);
    expect(balance).to.equal(0);
  });


});