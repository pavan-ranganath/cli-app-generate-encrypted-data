#!/usr/bin/env ts-node

import * as fs from 'fs';
import csvParser from 'csv-parser';
import * as csvWriter from 'csv-writer';
import {Command} from 'commander';
import {OpenFHE} from './openfhe/openfheCommon.service';

async function main() {
  const openFHE = new OpenFHE();
  await openFHE.initializeOpenFHE();
  openFHE.initializeCryptoContext();

  // Replace with the actual path to the public key file
  const dataHolderPublicKey = fs.readFileSync(
    'DEMO_3_HE_KEYS/HEpublicKey@egs.org_public.binary',
  );

  // Custom encryption and key generation functions
  function generateKey(): {secretKey: any; publicKey: any} {
    return openFHE.generateKeyPair();
  }

  function encryptString(value: string, key: any): any {
    const ct = openFHE.encryptString(value, key);
    const ctStr = openFHE.createCipherTextString(ct);
    return ctStr;
  }

  function encryptNumber(value: number, key: any): any {
    const ct = openFHE.encryptNumberOnly(value, key);
    const ctStr = openFHE.createCipherTextString(ct);
    return ctStr;
  }

  async function generatePREKey(ownerKey: any): Promise<Uint8Array> {
    const PREKey = openFHE.genearateProxyEncKey(dataHolderPublicKey, ownerKey);
    return openFHE.serializeEvalKeyToBuffer(PREKey);
  }

  // CLI setup
  const program = new Command();
  program
    .description('Encrypt a CSV file and generate PRE keys')
    .requiredOption('-i, --input <path>', 'Path to the input CSV file')
    .requiredOption('-o, --output <path>', 'Path to save the output CSV file')
    .option(
      '-k, --keys <columns>',
      'Comma-separated list of column names to skip encryption',
      value => value.split(','),
      [],
    );

  program.parse(process.argv);

  const {input, output, keys} = program.opts();

  // Process CSV
  async function processCSV(
    inputPath: string,
    outputPath: string,
    skipColumns: string[],
  ) {
    const rows: any[] = [];
    const headerKeys: string[] = [];

    // Read CSV
    fs.createReadStream(inputPath)
      .pipe(csvParser())
      .on('headers', (headers: any) => {
        headerKeys.push(...headers);
      })
      .on('data', (data: any) => {
        rows.push(data);
      })
      .on('end', async () => {
        // Process rows
        const encryptedRows = await Promise.all(
          rows.map(async row => {
            const encryptionKey = generateKey();
            const newRow: any = {...row};

            for (const [key, value] of Object.entries(row)) {
              if (skipColumns.includes(key)) {
                // Skip encryption for specified columns
                continue;
              }

              if (!value) {
                continue; // Skip empty fields
              }

              if (!isNaN(Number(value))) {
                // Encrypt number fields
                newRow[key] = encryptNumber(Number(value), encryptionKey);
              } else {
                // Encrypt string fields
                newRow[key] = encryptString(value as string, encryptionKey);
              }
            }

            // Add PRE key column
            newRow['PRE_key'] = (
              await generatePREKey(encryptionKey)
            ).toString();
            return newRow;
          }),
        );

        // Write to output CSV
        const writer = csvWriter.createObjectCsvWriter({
          path: outputPath,
          header: [
            ...headerKeys.map(key => ({id: key, title: key})),
            {id: 'PRE_key', title: 'PRE_key'},
          ],
        });

        await writer.writeRecords(encryptedRows);
        console.log(`Encrypted CSV saved to ${outputPath}`);
      });
  }

  // Execute
  await processCSV(input, output, keys);
}

// Run the script
main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
