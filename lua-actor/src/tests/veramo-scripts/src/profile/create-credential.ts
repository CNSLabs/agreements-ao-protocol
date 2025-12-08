import { agent } from '../veramo/setup.js'
import fs, { readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import { fileURLToPath } from 'url'
import { ethers } from 'ethers'

const testDir = '../../../'
const inputDirname = fileURLToPath(new URL(`${testDir}/profile/unwrapped`, import.meta.url))
const outputDir = fileURLToPath(new URL(`${testDir}/profile/wrapped`, import.meta.url))
if (!fs.existsSync(outputDir)){
  fs.mkdirSync(outputDir);
}

const agreement = JSON.parse(readFileSync(join(inputDirname, 'profile-agreement.json'), 'utf-8'));

// Read all input files
const inputFiles = {
  activation: JSON.parse(readFileSync(join(inputDirname, 'input-profile-activation.json'), 'utf-8')),
  update: JSON.parse(readFileSync(join(inputDirname, 'input-profile-update.json'), 'utf-8')),
  update2: JSON.parse(readFileSync(join(inputDirname, 'input-profile-update-2.json'), 'utf-8')),
  deactivation: JSON.parse(readFileSync(join(inputDirname, 'input-profile-deactivation.json'), 'utf-8')),
  reactivation: JSON.parse(readFileSync(join(inputDirname, 'input-profile-reactivation.json'), 'utf-8')),
  updatePartial: JSON.parse(readFileSync(join(inputDirname, 'input-profile-update-partial.json'), 'utf-8'))
};

async function writeVc(params, name) {
  const vc = await agent.createVerifiableCredential(params);
  const isValid = await agent.verifyCredential({ credential: vc })
  if (!isValid) {
    throw new Error(`Generated an invalid VC given params: ${JSON.stringify(params)}`);
  }
  // Use consistent naming with unwrapped version, just add .wrapped suffix
  const filename = `${name}.wrapped.json`;
  const vcStr = JSON.stringify(vc, null, 2);
  writeFileSync(join(outputDir, filename), vcStr);
  console.log(`Saved VC to ./${outputDir}/${filename}`);
  return { vc, vcStr, filename };
}

const didStrToEthAddress = didStr => didStr.slice(didStr.lastIndexOf(":") + 1);

async function main() {
  const user = await agent.didManagerGetByAlias({ alias: 'partyA' })
  const userEthAddress = didStrToEthAddress(user.did);

  try {
    // Create wrapped profile agreement
    const agreementParams = {
      credential: {
        issuer: { id: user.did },
        credentialSubject: {
          id: "did:example:profile-1",
          agreement: Buffer.from(JSON.stringify(agreement)).toString('base64'),
          params: {
            userEthAddress,
            isActive: false,
          }
        },
        type: ['VerifiableCredential','AgreementCredential'],
      },
      proofFormat: 'EthereumEip712Signature2021',
    };
    const { vcStr } = await writeVc(agreementParams, `profile-agreement`);
    const agreementDocHash = ethers.keccak256(new TextEncoder().encode(vcStr));

    // Set the documentHash for all input VCs
    Object.values(inputFiles).forEach(input => {
      input.documentHash = agreementDocHash;
    });

    // Create wrapped versions of all input files
    for (const [key, input] of Object.entries(inputFiles)) {
      const inputParams = {
        credential: {
          issuer: { id: user.did },
          credentialSubject: input,
          type: ['VerifiableCredential','AgreementInputCredential'],
        },
        proofFormat: 'EthereumEip712Signature2021',
      };
      await writeVc(inputParams, `input-profile-${key}`);
    }

  } catch(e) {
    console.error("Error", e)
  }
}

main().catch(console.log) 