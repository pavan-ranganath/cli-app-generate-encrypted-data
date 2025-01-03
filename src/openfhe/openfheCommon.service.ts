import type {Buffer} from 'buffer';
import {saveAs} from 'file-saver';
import JSZip from 'jszip';
import {
  ENCRYPTED_SSN_FILE_NAME,
  PRIVATE_KEY_FILENAME,
  PUBLIC_KEY_FILENAME,
  KEYS_DEFAULY_FILENAME,
} from '../constants';
import OpenFHEModule from './openfhe';

const SPACE_FILL_CHARACTER_ASCII = 0;

/**
 * Converts a vector object from the OpenFHE library to a regular JavaScript array.
 *
 * @param {object} vec - The vector object from OpenFHE.
 * @returns {number[]} - An array containing the elements from the vector.
 */
export function copyVecToJs(vec: {
  size: () => any;
  get: (arg0: number) => any;
}): number[] {
  return Array.from({length: vec.size()}, (_, idx) => vec.get(idx));
}

/**
 * Pads an array with zeros to a specified length.
 *
 * This function is used to ensure that input arrays have the same length
 * as required by the CKKS context.
 *
 * @param {number[]} inputVal - The array to be padded.
 * @param {number} slots - The desired length after padding.
 * @returns {number[]} - The padded array.
 */
export function padArray(inputVal: number[], slots: number): number[] {
  const paddingLength = slots - inputVal.length;
  const paddedVal = Array.from<number>({length: Math.max(paddingLength, 0)})
    .fill(0)
    .concat(inputVal);
  return paddedVal;
}

/**
 * Pads an array with a specific character for string input.
 *
 * This function ensures that string inputs have the same length
 * as required by the CKKS context. It pads with a space character
 * (ASCII code 0) by default.
 *
 * @param {any[]} inputVal - The array to be padded (containing string elements).
 * @param {number} slots - The desired length after padding.
 * @returns {any[]} - The padded array.
 */
function padArrayForStringInput(inputVal: any[], slots: number) {
  const paddingLength = slots - inputVal.length;
  const paddedVal = Array.from(inputVal).concat(
    Array.from({length: Math.max(paddingLength, 0)}).fill(
      SPACE_FILL_CHARACTER_ASCII,
    ),
  );
  return paddedVal;
}

/**
 * Converts a string to an array of UTF-16 code units.
 *
 * This function prepares string data for encryption by encoding each character
 * as its corresponding UTF-16 code unit.
 *
 * @param {string} inputString - The string to be converted.
 * @returns {number[]} - An array containing the UTF-16 code units of the string.
 */
export function stringToInt(inputString: string): number[] {
  // Split the input string into an array of characters
  // Map each character directly to its corresponding code unit
  return inputString.split('').map(char => char.charCodeAt(0));
}

/**
 * Converts an array of UTF-16 code units to a string.
 *
 * This function decodes encrypted string data by converting each UTF-16 code unit
 * back to its corresponding character.
 *
 * @param {number[]} intList - The array of UTF-16 code units.
 * @returns {string} - The decoded string.
 */
export function intToString(intList: number[]) {
  // Map each code unit to its corresponding character using String.fromCharCode()
  // and store the characters in an array
  const charArray = intList.map(num => String.fromCharCode(num));

  // Join the characters in the array into a single string and return it
  return charArray.join('');
}

/**
 * Enumeration for scaling techniques used in CKKS context.
 */
enum ScalingTechnique {
  FIXEDAUTO = 'FIXEDAUTO',
  FLEXIBLEAUTOEXT = 'FLEXIBLEAUTOEXT',
}

/**
 * Enumeration for security levels used in CKKS context.
 *
 * You can add other security levels here as needed.
 */
enum SecurityLevel {
  HEStd_NotSet = 'HEStd_NotSet',
  // Add other security levels as needed
}

/**
 * Enumeration for BINFHE parameter sets used in CKKS context.
 *
 * Each parameter set defines specific parameters for the binary FHE component
 * used within the CKKS scheme.
 */
enum BINFHEParamSet {
  TOY = 'TOY',
  // Add other parameter sets as needed
}

/**
 * Enumeration for serialization types used in CKKS context.
 *
 * You can add other serialization types here as needed.
 */
enum SERTYPE {
  BINARY = 'BINARY',
  JSON = 'JSON',
}
// function customLocateFile(path: string, scriptDirectory: any) {
//   if (!scriptDirectory.startsWith('http')) {
//     return `public/${path}`;
//   }
//   return `/${path}`;
//   // Your custom logic to locate the file
// }
export class OpenFHE {
  // Protected properties to allow access in derived classes
  protected scTech: ScalingTechnique =
    ScalingTechnique.FIXEDAUTO; /** Default scaling technique */
  protected multDepth = 17; /** Default multiplicative depth */
  protected scaleModSize = 50; /** Default scaling modulus size */
  protected firstModSize = 57; /** Default first modulus size */
  protected ringDim = 4096; /** Default ring dimension */
  protected sl: SecurityLevel =
    SecurityLevel.HEStd_NotSet; /** Default security level */
  protected slBin: BINFHEParamSet =
    BINFHEParamSet.TOY; /** Default BINFHE parameter set */
  protected logQ_ccLWE = 25; /** Default log Q for FHEW */
  protected slots = 32; /** Default number of slots */
  protected batchSize = this.slots; /** Default batch size */
  protected sertype: SERTYPE = SERTYPE.BINARY; /** Default serialization type */

  private openFHEModule: any =
    null; /** Reference to the OpenFHE library module */
  public cc: any = null; /** Cryptographic context object */
  public keys: any = null; /** Cryptographic keys object */

  /**
   * Constructor for the CKKSContext class.
   *
   * @param {ScalingTechnique} [scTech] - The scaling technique to use (optional).
   * @param {number} [multDepth] - The multiplicative depth (optional).
   * @param {number} [scaleModSize] - The scaling modulus size (optional).
   * @param {number} [firstModSize] - The first modulus size (optional).
   * @param {number} [ringDim] - The ring dimension (optional).
   * @param {SecurityLevel} [sl] - The security level (optional).
   * @param {BINFHEParamSet} [slBin] - The BINFHE parameter set (optional).
   * @param {number} [logQ_ccLWE] - The log Q for FHEW (optional).
   * @param {number} [slots] - The number of slots (optional).
   * @param {number} [batchSize] - The batch size (optional).
   * @param {SERTYPE} [sertype] - The serialization type (optional).
   */
  constructor(
    scTech?: ScalingTechnique,
    multDepth?: number,
    scaleModSize?: number,
    firstModSize?: number,
    ringDim?: number,
    sl?: SecurityLevel,
    slBin?: BINFHEParamSet,
    logQ_ccLWE?: number,
    slots?: number,
    batchSize?: number,
    sertype?: SERTYPE,
  ) {
    // Override default values if provided
    if (scTech) {
      this.scTech = scTech;
    }
    if (multDepth) {
      this.multDepth = multDepth;
    }
    if (scaleModSize) {
      this.scaleModSize = scaleModSize;
    }
    if (firstModSize) {
      this.firstModSize = firstModSize;
    }
    if (ringDim) {
      this.ringDim = ringDim;
    }
    if (sl) {
      this.sl = sl;
    }
    if (slBin) {
      this.slBin = slBin;
    }
    if (logQ_ccLWE) {
      this.logQ_ccLWE = logQ_ccLWE;
    }
    if (slots) {
      this.slots = slots;
    }
    if (batchSize) {
      this.batchSize = batchSize;
    }
    if (sertype) {
      this.sertype = sertype;
    }

    this.openFHEModule = null;
    this.cc = null;
    this.keys = null;
  }

  /**
   * Asynchronously initializes the OpenFHE library module.
   */
  async initializeOpenFHE() {
    this.openFHEModule = await OpenFHEModule();
  }

  /**
   * Utility function to retrieve internal mapping for scaling techniques.
   * @private
   */
  private getScalingTechniques() {
    return {
      [ScalingTechnique.FIXEDAUTO]:
        this.openFHEModule.ScalingTechnique.FIXEDAUTO,
      [ScalingTechnique.FLEXIBLEAUTOEXT]:
        this.openFHEModule.ScalingTechnique.FLEXIBLEAUTOEXT,
    };
  }

  /**
   * Utility function to retrieve internal mapping for security level
   * @private
   */
  private getSecurityLevels() {
    return {
      [SecurityLevel.HEStd_NotSet]:
        this.openFHEModule.SecurityLevel.HEStd_NotSet,
      // Add other security levels as needed
    };
  }

  /**
   * Utility function to retrieve internal mapping for serialization types
   * @private
   */
  private getSerializeType() {
    return {
      [SERTYPE.BINARY]: this.openFHEModule.SerType.BINARY,
      [SERTYPE.JSON]: this.openFHEModule.SerType.JSON,
    };
  }

  /**
   * Utility function to retrieve internal mapping for BINFHE params
   * @private
   */
  private getBINFHEParams() {
    return {
      [BINFHEParamSet.TOY]: this.openFHEModule.BINFHE_PARAMSET.TOY,
      // Add other BINFHE parameters as needed
    };
  }

  /**
   * Gets the CryptoContext object.
   * @returns {any} The CryptoContext object.
   */
  get CryptoContext(): any {
    return this.cc;
  }

  /**
   * Sets the CryptoContext object.
   * @param {any} cc - The CryptoContext object to set.
   */
  public set CryptoContext(cc: any) {
    this.cc = cc;
  }

  /**
   * Gets the keys object.
   * @returns {any} The keys object.
   */
  get Keys(): any {
    return this.keys;
  }

  public set Keys(keypair: any) {
    this.keys = keypair;
  }

  /**
   * Gets the OpenFHEModule.
   * @returns {any} The OpenFHEModule.
   */
  get OpenFHEModule(): any {
    return this.openFHEModule;
  }

  /**
   * Initializes the CKKS cryptographic context.
   *
   * This function creates a new CKKS cryptographic context using the specified parameters
   * and enables necessary features for homomorphic encryption operations.
   *
   * @throws {Error} - If the OpenFHE module is not initialized or an error occurs during initialization.
   */
  initializeCryptoContext() {
    if (!this.openFHEModule) {
      throw new Error('openFHEModule is not initialized');
    }

    try {
      const scTech = this.getScalingTechniques()[this.scTech];
      let multDepth = this.multDepth;

      if (
        scTech === this.getScalingTechniques()[ScalingTechnique.FLEXIBLEAUTOEXT]
      ) {
        multDepth += 1;
      }

      const parameters = new this.openFHEModule.CCParamsCryptoContextCKKSRNS();
      parameters.SetMultiplicativeDepth(multDepth);
      parameters.SetScalingModSize(this.scaleModSize);
      parameters.SetFirstModSize(this.firstModSize);
      parameters.SetScalingTechnique(scTech);
      parameters.SetSecurityLevel(this.getSecurityLevels()[this.sl]);
      parameters.SetRingDim(this.ringDim);
      parameters.SetBatchSize(this.batchSize);
      parameters.SetSecretKeyDist(
        this.openFHEModule.SecretKeyDist.UNIFORM_TERNARY,
      );
      parameters.SetKeySwitchTechnique(
        this.openFHEModule.KeySwitchTechnique.HYBRID,
      );
      parameters.SetNumLargeDigits(3);

      this.cc = new this.openFHEModule.GenCryptoContextCKKS(parameters);

      // Enable features
      this.cc.Enable(this.openFHEModule.PKESchemeFeature.PKE);
      this.cc.Enable(this.openFHEModule.PKESchemeFeature.KEYSWITCH);
      this.cc.Enable(this.openFHEModule.PKESchemeFeature.LEVELEDSHE);
      this.cc.Enable(this.openFHEModule.PKESchemeFeature.ADVANCEDSHE);
      this.cc.Enable(this.openFHEModule.PKESchemeFeature.SCHEMESWITCH);
      this.cc.Enable(this.openFHEModule.PKESchemeFeature.PRE);

      console.debug(
        `CKKS scheme is using ring dimension ${this.cc.GetRingDimension()},\n and number of slots ${
          this.slots
        }\n and supports a multiplicative depth of ${multDepth}\n`,
      );
    } catch (error) {
      const msg =
        typeof error === 'number'
          ? this.openFHEModule.getExceptionMessage(error)
          : error;
      throw new Error(msg);
    }
  }

  /**
   * Generates cryptographic keys for the CKKS context.
   *
   * This function generates a public key and a secret key for the initialized CKKS context.
   * It also generates evaluation sum and multiplication keys.
   *
   * @throws {Error} - If the CKKS context is not initialized.
   */
  generateKey() {
    if (!this.cc) {
      throw new Error('CKKSContext is not initialized');
    }
    this.generateKeyPair();
    this.cc.EvalSumKeyGen(this.keys.secretKey);
    this.cc.EvalMultKeyGen(this.keys.secretKey);
    console.debug('Completed keygen');
  }

  generateKeyPair() {
    if (!this.cc) {
      throw new Error('CKKSContext is not initialized');
    }
    return this.cc.KeyGen();
  }

  /**
   * Adds scheme switching capabilities to the CKKS context.
   *
   * This function sets up the scheme switching parameters and generates the necessary keys for
   * performing scheme switching operations.
   *
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  addschemeSwitchingCC() {
    if (!this.cc || !this.keys) {
      throw new Error('CKKSContext and keys is not initialized');
    }
    try {
      // Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
      const params = new this.openFHEModule.SchSwchParams();
      params.SetSecurityLevelCKKS(this.getSecurityLevels()[this.sl]);
      params.SetSecurityLevelFHEW(this.getBINFHEParams()[this.slBin]);
      params.SetCtxtModSizeFHEWLargePrec(this.logQ_ccLWE);
      params.SetNumSlotsCKKS(this.slots);
      params.SetNumValues(this.slots);

      const privateKeyFHEW = this.cc.EvalSchemeSwitchingSetup(params);
      // const ccLWE = this.cc.GetBinCCForSchemeSwitch();
      this.cc.EvalSchemeSwitchingKeyGen(this.keys, privateKeyFHEW);
    } catch (error) {
      const msg =
        typeof error === 'number'
          ? this.openFHEModule.getExceptionMessage(error)
          : error;
      throw new Error(msg);
    } finally {
      console.debug('Completed schemeSwitchingCC');
    }
  }

  /**
   * Packs a vector of numbers into a plaintext and encrypts it using the CKKS context.
   *
   * @param {number[]} vector - The vector of numbers to be packed and encrypted.
   * @returns {any} - The encrypted ciphertext.
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  packAndEncryptString(vector: number[]): any {
    if (!this.cc || !this.keys) {
      throw new Error('CKKSContext is not initialized');
    }
    const packedPlaintext = this.encodedVectorString(vector);
    const ciphertext = this.cc.Encrypt(this.keys.publicKey, packedPlaintext);
    return ciphertext;
  }

  /**
   * Encodes a vector of numbers into a packed plaintext.
   *
   * @param {number[]} vector - The vector of numbers to be encoded.
   * @returns {any} - The encoded packed plaintext.
   */
  encodedVectorNumber(vector: number[]): any {
    const vectorOutput = new this.openFHEModule.VectorDouble(
      padArray(vector, this.slots),
    );
    return this.cc.MakeCKKSPackedPlaintext(vectorOutput);
  }

  /**
   * Encrypts a single number using the CKKS context.
   *
   * @param {number} num - The number to be encrypted.
   * @returns {any} - The encrypted ciphertext.
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  encryptNumber(num: number): any {
    if (!this.cc || !this.keys) {
      throw new Error('CKKSContext is not initialized');
    }
    const encodedVector = this.encodedVectorNumber([num]);
    const ciphertext = this.cc.Encrypt(this.keys.publicKey, encodedVector);
    return ciphertext;
  }

  /**
   * Encrypts a single number using the CKKS context (optimized version).
   *
   * @param {number} num - The number to be encrypted.
   * @returns {any} - The encrypted ciphertext.
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  encryptNumberOnly(num: number, key: any): any {
    if (!this.cc) {
      throw new Error('CKKSContext is not initialized');
    }
    const encodedVector = new this.openFHEModule.VectorDouble([num]);

    const ciphertext = this.cc.Encrypt(
      key.publicKey,
      this.cc.MakeCKKSPackedPlaintext(encodedVector),
    );
    return ciphertext;
  }

  /**
   * Encodes a vector of strings into a packed plaintext.
   *
   * @param {number[]} vector - The vector of strings to be encoded.
   * @returns {any} - The encoded packed plaintext.
   */
  encodedVectorString(vector: number[]): any {
    const vectorOutput = new this.openFHEModule.VectorDouble(
      padArrayForStringInput(vector, this.slots),
    );
    return this.cc.MakeCKKSPackedPlaintext(vectorOutput);
  }

  /**
   * Encrypts a string using the CKKS context.
   *
   * @param {string} str - The string to be encrypted.
   * @returns {any} - The encrypted ciphertext.
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  encryptString(str: string, keys: any): any {
    if (!this.cc) {
      throw new Error('CKKSContext is not initialized');
    }
    const strToIntVector = stringToInt(str);
    const encodedVector = this.encodedVectorString(strToIntVector);
    const ciphertext = this.cc.Encrypt(keys.publicKey, encodedVector);
    return ciphertext;
  }

  /**
   * Serializes the cryptographic context to a buffer.
   *
   * @returns {any} - The serialized cryptographic context as a buffer.
   */
  serializeCryptoContextToBuffer(): any {
    return this.openFHEModule.SerializeCryptoContextToBuffer(
      this.cc,
      this.getSerializeType()[this.sertype],
    );
  }

  /**
   * Serializes the public key to a buffer.
   *
   * @returns {any} - The serialized public key as a buffer.
   */
  serializePublicKeyToBuffer(): any {
    return this.openFHEModule.SerializePublicKeyToBuffer(
      this.keys.publicKey,
      this.getSerializeType()[this.sertype],
    );
  }

  /**
   * Serializes the private key to buffer.
   * @returns {Buffer} - public key buffer
   */
  serializePrivateKeyToBuffer(): Buffer {
    return this.openFHEModule.SerializePrivateKeyToBuffer(
      this.keys.secretKey,
      this.getSerializeType()[this.sertype],
    );
  }

  /**
   *  Serializes the public and private key to buffer.
   * @returns {publicKey: Buffer,privateKey: Buffer}
   */
  serializeKeyPairToBuffer(): {publicKey: Buffer; privateKey: Buffer} {
    return {
      publicKey: this.serializePublicKeyToBuffer(),
      privateKey: this.serializePrivateKeyToBuffer(),
    };
  }

  /**
   * Serializes the evaluation sum key to a buffer.
   *
   * @returns {any} - The serialized evaluation sum key as a buffer.
   */
  serializeEvalSumKeyToBuffer(): any {
    return this.cc.SerializeEvalSumKeyToBuffer(
      this.getSerializeType()[this.sertype],
    );
  }

  /**
   * Creates a ciphertext buffer from the given ciphertext.
   *
   * @param {any} cipherText - The ciphertext to be serialized.
   * @returns {any} - The serialized ciphertext as a buffer.
   */
  createCipherTextBuffer(cipherText: any): any {
    return this.openFHEModule.SerializeCiphertextToBuffer(
      cipherText,
      this.getSerializeType()[this.sertype],
    );
  }

  createCipherTextString(cipherText: any): any {
    const strData = this.openFHEModule.SerializeCiphertextToString(cipherText);
    return strData;
  }

  /**
   * Downloads a ciphertext as a file.
   *
   * @param {any} cipherText - The ciphertext to be downloaded.
   */
  downloadCipherText(cipherText: any) {
    const bufferedCipherText = this.createCipherTextBuffer(cipherText);
    const blobCipherText = new Blob([bufferedCipherText], {
      type: 'application/octet-stream',
    });
    saveAs(blobCipherText, ENCRYPTED_SSN_FILE_NAME);
  }

  /**
   * Serializes an evaluation key to a buffer.
   *
   * @param {any} evalKey - The evaluation key to be serialized.
   * @returns {Promise<Uint8Array>} - A promise resolving to the serialized evaluation key as a Uint8Array.
   */
  async serializeEvalKeyToBuffer(evalKey: any): Promise<Uint8Array> {
    return this.openFHEModule.SerializeEvalKeyToBuffer(
      evalKey,
      this.getSerializeType()[this.sertype],
    );
  }

  deserializeEvalKeyFromBuffer(evalKeyBuffery: any) {
    return this.openFHEModule.DerializeEvalKeyToBuffer(
      evalKeyBuffery,
      this.getSerializeType()[this.sertype],
    );
  }

  /**
   * Deserializes a ciphertext buffer and returns the ciphertext object.
   *
   * @param {Buffer} ctBuffer - The ciphertext buffer to be deserialized.
   * @returns {any} - The deserialized ciphertext object.
   * @throws {Error} - If there's an error during deserialization.
   */
  deserializeCipherTextBuffer(ctBuffer: any): any {
    return this.openFHEModule.DeserializeCiphertextFromBuffer(
      ctBuffer,
      this.getSerializeType()[this.sertype],
    );
  }

  /**
   * Deserializes a ciphertext string and returns the ciphertext object.
   *
   * @param {string} ctStr - The ciphertext buffer to be deserialized.
   * @returns {any} - The deserialized ciphertext object.
   * @throws {Error} - If there's an error during deserialization.
   */
  deserializeCipherTextString(ctStr: string): any {
    return this.openFHEModule.DerializeCiphertextFromString(ctStr);
  }

  /**
   * Deserializes a public key buffer and returns the public key object.
   *
   * @param {Buffer} pubKey - The public key buffer to be deserialized.
   * @returns {any} - The deserialized public key object.
   * @throws {Error} - If there's an error during deserialization.
   */
  deserializePublicKeyBuffer(pubKey: any): any {
    return this.openFHEModule.DeserializePublicKeyFromBuffer(
      pubKey,
      this.getSerializeType()[this.sertype],
    );
  }

  deserializeSecretKeyBuffer(pubKey: any) {
    return this.openFHEModule.DeserializePrivateKeyFromBuffer(
      pubKey,
      this.getSerializeType()[this.sertype],
    );
  }

  deserializeEvalSumKeyFromBuffer(evalSumKey: any) {
    return this.cc.DeserializeEvalSumKeyFromBuffer(
      evalSumKey,
      this.getSerializeType()[this.sertype],
    );
  }

  /**
   * Re-encrypts a ciphertext using a different public key.
   *
   * @param {any} pubKey - The new public key for re-encryption.
   * @param {any} ciphertext - The ciphertext to be re-encrypted.
   * @returns {any} - The re-encrypted ciphertext.
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  reEncryptData(pubKey: any, ciphertext: any): any {
    if (!this.cc || !this.keys) {
      throw new Error('CKKSContext is not initialized');
    }

    const reencryptionKey = this.cc.ReKeyGenPrivPub(
      this.keys.secretKey,
      pubKey,
    );
    const reEncryptedCiphertext = this.cc.ReEncrypt(
      reencryptionKey,
      ciphertext,
    );
    return reEncryptedCiphertext;
  }

  compressCipherText(ct: any) {
    return this.cc.Compress(ct, 1);
  }

  /**
   * Generates a proxy encryption key for a given public key.
   *
   * @param {Buffer} pubKeyBuffer - The serialized public key.
   * @returns {any} - The generated proxy encryption key.
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  genearateProxyEncKey(pubKeyBuffer: Buffer, key: any): any {
    if (!this.cc) {
      throw new Error('CKKSContext is not initialized');
    }
    const pubKey = this.deserializePublicKeyBuffer(pubKeyBuffer);
    const reencryptionKey = this.cc.ReKeyGenPrivPub(key.secretKey, pubKey);
    return reencryptionKey;
  }

  /**
   * Decrypt a ciphertext buffer and returns the decrypted plaintext.
   *
   * @param {any} ctBuffer - The ciphertext buffer to be deserialized.
   * @returns {{ pt: any; decodeNumberPlainText: () => string; }} - An object containing the decrypted plaintext and a function to decode it.
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  decryptBufferCipherText(ctBuffer: Buffer): {
    pt: any;
    decodeNumberPlainText: () => string;
    decodeStringPlainText: () => string;
  } {
    if (!this.cc || !this.keys) {
      throw new Error('CKKSContext is not initialized');
    }
    const ct = this.deserializeCipherTextBuffer(ctBuffer);
    const pt = this.cc.Decrypt(this.keys.secretKey, ct);
    return {
      pt, // Return the decrypted plaintext
      decodeNumberPlainText: () => this.decodeNumberPlainText(pt), // Decode when called
      decodeStringPlainText: () => this.decodeStringPlainText(pt), // Decode when called
    };
  }

  /**
   * Decrypt a ciphertext buffer and returns the decrypted plaintext.
   *
   * @param {string} ctString - The ciphertext buffer to be deserialized.
   * @returns {{ pt: any; decodeNumberPlainText: () => string; }} - An object containing the decrypted plaintext and a function to decode it.
   * @throws {Error} - If the CKKS context or keys are not initialized.
   */
  decryptStringCipherText(ctString: string): {
    pt: any;
    decodeNumberPlainText: () => string;
    decodeStringPlainText: () => string;
  } {
    if (!this.cc || !this.keys) {
      throw new Error('CKKSContext is not initialized');
    }
    const ct = this.deserializeCipherTextString(ctString);
    const pt = this.cc.Decrypt(this.keys.secretKey, ct);
    return {
      pt, // Return the decrypted plaintext
      decodeNumberPlainText: () => this.decodeNumberPlainText(pt), // Decode when called
      decodeStringPlainText: () => this.decodeStringPlainText(pt), // Decode when called
    };
  }

  decodeStringPlainText(pt: any): string {
    const vectors = copyVecToJs(pt.GetRealPackedValue());
    return intToString(vectors.map(number => Math.round(number)));
  }

  /**
   * Decodes a plaintext value as a number.
   *
   * @param {any} pt - The plaintext value to be decoded.
   * @returns {string} - The decoded number as a string.
   */
  decodeNumberPlainText(pt: any): string {
    return copyVecToJs(pt.GetRealPackedValue())[0]?.toFixed(3) || 'Error';
  }

  /**
   * Downloads cryptographic keys as a ZIP file.
   *
   * This function serializes the public and private keys, creates a ZIP file,
   * and initiates the download.
   *
   * @returns {Promise<void>} - A promise that resolves when the download is complete.
   */
  async downloadKeys(): Promise<void> {
    const zip = new JSZip();

    const addBufferToZip = (buffer: Buffer | null, fileName: string) => {
      if (buffer && fileName) {
        zip.file(fileName, buffer);
      }
    };

    const buffers: {
      privateKeyBuffer: Buffer | null;
      publicKeyBuffer: Buffer | null;
    } = {
      privateKeyBuffer: null,
      publicKeyBuffer: null,
    };
    buffers.publicKeyBuffer = this.openFHEModule.SerializePublicKeyToBuffer(
      this.keys.publicKey,
      this.getSerializeType()[this.sertype],
    );
    buffers.privateKeyBuffer = this.openFHEModule.SerializePrivateKeyToBuffer(
      this.keys.secretKey,
      this.getSerializeType()[this.sertype],
    );
    addBufferToZip(buffers.privateKeyBuffer, PRIVATE_KEY_FILENAME);
    addBufferToZip(buffers.publicKeyBuffer, PUBLIC_KEY_FILENAME);
    const blob = await zip.generateAsync({type: 'blob'});
    saveAs(blob, KEYS_DEFAULY_FILENAME);
  }
}
