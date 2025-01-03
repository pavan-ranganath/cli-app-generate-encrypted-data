import type {Buffer} from 'buffer';
import {saveAs} from 'file-saver';
import JSZip from 'jszip';
export type FileNames = {
  cryptoContextFile: string;
  pubKeyFile: string;
  secretKeyFile: string;
  multKeyFile: string;
  rotKeyFile: string;
  FHEWtoCKKSSwitchKeyFile: string;
  binFHECryptoContextFile: string;
  binFHEBootRefreshKeyFile: string;
  binFHEBootRotKeyFile: string;
  keyIndexFile: string;
  baseRefreshKeyFile: string;
  baseSwitchingKeyFile: string;
};
/**
 * Defines the structure of buffers for storing cryptographic context data.
 *
 * @typedef {object} CryptoContextBuffers
 * @property {Buffer | null} cryptoContextBuffer - The buffer containing the serialized cryptographic context.
 * @property {Buffer | null} publicKeyBuffer - The buffer containing the serialized public key.
 * @property {Buffer | null} secretKeyBuffer - The buffer containing the serialized secret key.
 * @property {Buffer | null} evalMultKeyBuffer - The buffer containing the serialized evaluation multiplication key.
 * @property {Buffer | null} automorphismKeyBuffer - The buffer containing the serialized automorphism key.
 * @property {Buffer | null} FHEWtoCKKSSwitchKeyBuffer - The buffer containing the serialized FHEW to CKKS switching key.
 * @property {Buffer | null} binfheCryptoContextBuffer - The buffer containing the serialized binary FHE cryptographic context.
 * @property {Buffer | null} binFHEBootRefreshKeyBuffer - The buffer containing the serialized binary FHE boot refresh key.
 * @property {Buffer | null} binFHEBootRotKeyBuffer - The buffer containing the serialized binary FHE boot rotation key.
 * @property {Buffer | null} keyIndexBuffer - The buffer containing the serialized key index.
 * @property {{ [key: number]: { BSkey: Buffer; KSkey: Buffer } }[]} EvalKeyMappings - An array of key mappings, each containing a BSkey and KSkey.
 */
export type CryptoContextBuffers = {
  cryptoContextBuffer: Buffer | null;
  publicKeyBuffer: Buffer | null;
  secretKeyBuffer: Buffer | null;
  evalMultKeyBuffer: Buffer | null;
  automorphismKeyBuffer: Buffer | null;
  FHEWtoCKKSSwitchKeyBuffer: Buffer | null;
  binfheCryptoContextBuffer: Buffer | null;
  binFHEBootRefreshKeyBuffer: Buffer | null;
  binFHEBootRotKeyBuffer: Buffer | null;
  keyIndexBuffer: Buffer | null;
  EvalKeyMappings: {[key: number]: {BSkey: Buffer; KSkey: Buffer}}[];
};

/**
 * Base class for handling cryptographic context data and file operations.
 *
 * This class provides properties and methods for managing cryptographic context data, including
 * the cryptographic context itself, keys, and related data. It also handles file operations for
 * storing and retrieving serialized data.
 */
class DataAndLocation {
  cryptoContext: any = null;
  publicKey: any = null;
  secretKey: any = null;
  binFHECryptoContext: any = null;
  FHEWtoCKKSSwitchKey: any = null;
  dataDirectory = 'demoData';
  cryptoContextFile = 'cryptocontext.txt';
  pubKeyFile = 'key_pub.txt';
  secretKeyFile = 'key_secret.txt';
  multKeyFile = 'key_mult.txt';
  rotKeyFile = 'key_rot.txt';
  FHEWtoCKKSSwitchKeyFile = 'key_switch_fhew_ckks.txt';
  binFHECryptoContextFile = 'binfhe_cryptocontext.txt';
  binFHEBootRefreshKeyFile = 'key_binfhe_boot_refresh.txt';
  binFHEBootRotKeyFile = 'key_binfhe_boot_rot.txt';
  baseRefreshKeyFile = 'key_refresh.txt';
  baseSwitchingKeyFile = 'key_switching.txt';
  keyIndexFile = 'key_indices.txt';
  module: any = null;

  buffers: CryptoContextBuffers = {
    cryptoContextBuffer: null,
    publicKeyBuffer: null,
    secretKeyBuffer: null,
    evalMultKeyBuffer: null,
    automorphismKeyBuffer: null,
    FHEWtoCKKSSwitchKeyBuffer: null,
    binfheCryptoContextBuffer: null,
    binFHEBootRefreshKeyBuffer: null,
    binFHEBootRotKeyBuffer: null,
    keyIndexBuffer: null,
    EvalKeyMappings: [],
  };

  createMapFileName(index: number, baseFileName: string): string {
    return `${this.dataDirectory}/${index}_${baseFileName}`;
  }

  setDataDirectory(dir: string): void {
    if (!dir) {
      throw new Error('dir is an empty string');
    }

    // Remove slash if it is the last character in "dir"
    if (dir.slice(-1) === '/') {
      this.dataDirectory = dir.slice(0, -1);
    } else {
      this.dataDirectory = dir;
    }
  }
}
/**
 * Class responsible for serializing scheme-switching data for secure computation.
 *
 * This class inherits from `DataAndLocation` and provides functionalities for
 * serializing cryptographic contexts, keys, and other related data used in
 * scheme-switching homomorphic encryption. It utilizes buffers for efficient
 * storage and transmission.
 */
export class SchemeSwitchingDataSerializer extends DataAndLocation {
  /**
   * Serialization type used for the data.
   */
  SERTYPE: any;

  /**
   * Constructor for the class.
   *
   * @param {any} cryptoContext0 - The underlying cryptographic context object.
   * @param {any} publicKey0 - The public key used for encryption. (optional)
   * @param {any} privateKey0 - The private key used for decryption. (optional)
   */
  constructor(
    cryptoContext0: any = null,
    publicKey0: any = null,
    privateKey0: any = null,
  ) {
    super();
    this.cryptoContext = cryptoContext0;
    this.publicKey = publicKey0;
    this.secretKey = privateKey0;
    this.binFHECryptoContext = cryptoContext0
      ? cryptoContext0.GetBinCCForSchemeSwitch()
      : null;
    this.FHEWtoCKKSSwitchKey = cryptoContext0
      ? cryptoContext0.GetSwkFC()
      : null;
  }

  /**
   * Serializes all relevant data into buffers for storage or transmission.
   *
   * This function performs various checks for the existence of required objects
   * before proceeding with serialization. It then serializes the cryptographic
   * context, keys, and other data into separate buffers.
   *
   * @throws {Error} - If any required object is missing or serialization fails.
   */
  Serialize(): void {
    if (this.module === null) {
      throw new Error('OPENFHE module is None');
    }
    if (this.cryptoContext === null) {
      throw new Error('cryptoContext is None');
    }
    if (this.publicKey === null) {
      throw new Error('publicKey is None');
    }
    if (this.secretKey === null) {
      throw new Error('secretKey is None');
    }
    if (this.binFHECryptoContext === null) {
      throw new Error('binFHECryptoContext is None');
    }
    if (this.FHEWtoCKKSSwitchKey === null) {
      throw new Error('FHEWtoCKKSSwitchKey is None');
    }

    const serverCC = this.cryptoContext;

    // Serialize to buffers
    this.buffers.cryptoContextBuffer =
      this.module.SerializeCryptoContextToBuffer(
        this.cryptoContext,
        this.SERTYPE,
      );
    if (!this.buffers.cryptoContextBuffer) {
      throw new Error('Exception writing cryptocontext to buffer');
    }

    this.buffers.publicKeyBuffer = this.module.SerializePublicKeyToBuffer(
      this.publicKey,
      this.SERTYPE,
    );
    if (!this.buffers.publicKeyBuffer) {
      throw new Error('Exception writing publicKey to buffer');
    }

    this.buffers.secretKeyBuffer = this.module.SerializePrivateKeyToBuffer(
      this.secretKey,
      this.SERTYPE,
    );
    if (!this.buffers.secretKeyBuffer) {
      throw new Error('Exception writing secretKey to buffer');
    }

    this.buffers.evalMultKeyBuffer = serverCC.SerializeEvalMultKeyToBuffer(
      this.SERTYPE,
    );
    if (!this.buffers.evalMultKeyBuffer) {
      throw new Error('Error writing eval mult keys to buffer');
    }

    this.buffers.automorphismKeyBuffer =
      serverCC.SerializeEvalAutomorphismKeyToBuffer(this.SERTYPE);
    if (!this.buffers.automorphismKeyBuffer) {
      throw new Error('Error writing rotation keys to buffer');
    }

    this.buffers.FHEWtoCKKSSwitchKeyBuffer = this.module.SerializeSwkFC(
      this.FHEWtoCKKSSwitchKey,
      this.SERTYPE,
    );
    if (!this.buffers.FHEWtoCKKSSwitchKeyBuffer) {
      throw new Error('Exception writing FHEWtoCKKSSwitchKey to buffer');
    }

    this.buffers.binfheCryptoContextBuffer =
      this.module.SerializeBinFHECryptoContextToBuffer(
        this.binFHECryptoContext,
        this.SERTYPE,
      );
    if (!this.buffers.binfheCryptoContextBuffer) {
      throw new Error('Exception writing binFHECryptoContext to buffer');
    }

    this.buffers.binFHEBootRefreshKeyBuffer =
      this.module.SerializeBinFHERefreshKeyToBuffer(
        this.binFHECryptoContext.GetRefreshKey(),
        this.SERTYPE,
      );
    if (!this.buffers.binFHEBootRefreshKeyBuffer) {
      throw new Error('Exception writing binFHEBootRefreshKey to buffer');
    }

    this.buffers.binFHEBootRotKeyBuffer =
      this.module.SerializeBinFHESwitchingKeyToBuffer(
        this.binFHECryptoContext.GetSwitchKey(),
        this.SERTYPE,
      );
    if (!this.buffers.binFHEBootRotKeyBuffer) {
      throw new Error('Exception writing binFHEBootRotKey to buffer');
    }

    const indices = new this.module.VectorUint32();
    const BTKeyMap = this.binFHECryptoContext.GetBTKeyMap();
    const BTKeyMapArr = Array.from({length: BTKeyMap.keys().size()})
      .fill(0)
      .map((_, idx) => BTKeyMap.keys().get(idx));
    for (const [_, thekey] of Object.entries(BTKeyMapArr)) {
      const binFHEBSkeyKeyBuffer =
        this.module.SerializeBinFHERefreshKeyToBuffer(
          BTKeyMap.get(thekey).BSkey,
          this.SERTYPE,
        );
      if (!binFHEBSkeyKeyBuffer) {
        throw new Error('Exception writing BSkey to buffer');
      }

      const binFHEKSkeyBuffer = this.module.SerializeBinFHESwitchingKeyToBuffer(
        BTKeyMap.get(thekey).KSkey,
        this.SERTYPE,
      );
      if (!binFHEKSkeyBuffer) {
        throw new Error('Exception writing KSkey to buffer');
      }
      this.buffers.EvalKeyMappings.push({
        [thekey]: {
          BSkey: binFHEBSkeyKeyBuffer,
          KSkey: binFHEKSkeyBuffer,
        },
      });
      indices.push_back(thekey);
    }

    this.buffers.keyIndexBuffer = this.module.SerializeSeedSeqVector(
      indices,
      this.SERTYPE,
    );
    if (!this.buffers.keyIndexBuffer) {
      throw new Error('Exception writing indices to buffer');
    }
  }

  /**
   * Writes all serialized buffers to individual files using the provided filesystem object.
   *
   * This function iterates through all buffers and writes them to corresponding
   * files using the `writeFileSync` method of the provided filesystem object.
   * Additionally, it handles writing key mappings to separate files.
   *
   * @param {any} fs - The filesystem object used for writing files.
   * @throws {Error} - If any buffer or key mapping fails to write.
   */
  writeBuffersToFile(fs: any): void {
    const writeToFile = (buffer: Buffer | null, fileName: string) => {
      if (buffer && fileName) {
        fs.writeFileSync(`${this.dataDirectory}/${fileName}`, buffer);
      }
    };
    const writeKeyMappingToFile = (
      thekey: {BSkey: Buffer; KSkey: Buffer},
      index: number,
    ) => {
      const bskeyFileName = this.createMapFileName(
        index,
        this.baseRefreshKeyFile,
      );
      const kskeyFileName = this.createMapFileName(
        index,
        this.baseSwitchingKeyFile,
      );

      fs.writeFileSync(bskeyFileName, thekey.BSkey);
      fs.writeFileSync(kskeyFileName, thekey.KSkey);
    };

    writeToFile(this.buffers.cryptoContextBuffer, this.cryptoContextFile);
    writeToFile(this.buffers.publicKeyBuffer, this.pubKeyFile);
    writeToFile(this.buffers.evalMultKeyBuffer, this.multKeyFile);
    writeToFile(this.buffers.automorphismKeyBuffer, this.rotKeyFile);
    writeToFile(
      this.buffers.FHEWtoCKKSSwitchKeyBuffer,
      this.FHEWtoCKKSSwitchKeyFile,
    );
    writeToFile(
      this.buffers.binfheCryptoContextBuffer,
      this.binFHECryptoContextFile,
    );
    writeToFile(
      this.buffers.binFHEBootRefreshKeyBuffer,
      this.binFHEBootRefreshKeyFile,
    );
    writeToFile(this.buffers.binFHEBootRotKeyBuffer, this.binFHEBootRotKeyFile);
    writeToFile(this.buffers.keyIndexBuffer, this.keyIndexFile);

    this.buffers.EvalKeyMappings.forEach((mapping, _) => {
      const key = Object.keys(mapping)[0];
      const thekey = mapping[Number(key)];
      if (thekey) {
        writeKeyMappingToFile(thekey, Number(key));
      }
    });
  }

  /**
   * Generates an object containing filenames for all serialized data.
   *
   * This function creates a `FileNames` object with properties corresponding to
   * the filenames of each serialized buffer and key mapping file.
   *
   * @returns {FileNames} - An object containing filenames for all serialized data.
   */
  getFileNames(): FileNames {
    return {
      cryptoContextFile: this.cryptoContextFile,
      pubKeyFile: this.pubKeyFile,
      secretKeyFile: this.secretKeyFile,
      multKeyFile: this.multKeyFile,
      rotKeyFile: this.rotKeyFile,
      FHEWtoCKKSSwitchKeyFile: this.FHEWtoCKKSSwitchKeyFile,
      binFHECryptoContextFile: this.binFHECryptoContextFile,
      binFHEBootRefreshKeyFile: this.binFHEBootRefreshKeyFile,
      binFHEBootRotKeyFile: this.binFHEBootRotKeyFile,
      keyIndexFile: this.keyIndexFile,
      baseRefreshKeyFile: this.baseRefreshKeyFile,
      baseSwitchingKeyFile: this.baseSwitchingKeyFile,
    };
  }

  /**
   * Creates a downloadable file containing all serialized data using a web worker (if available).
   *
   * This function utilizes a web worker to handle the process of creating a
   * downloadable file. It sends the buffers and filenames to the worker for
   * processing and receives the downloadable file in chunks.
   *
   * @param {CryptoContextBuffers} buffers - The object containing all serialized buffers.
   * @param {FileNames} fileNames - The object containing filenames for all serialized data.
   * @param {Worker} workRef - The web worker reference (optional).
   * @returns {Promise<Uint8Array>} - A promise resolving to the downloaded file data as a Uint8Array.
   * @throws {Error} - If the worker is unavailable or an error occurs during download creation.
   */
  async createDownloadableFileViaWorker(
    buffers: CryptoContextBuffers,
    fileNames: FileNames,
    workRef: Worker,
  ): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      if (workRef) {
        const chunks: Uint8Array[] = [];

        workRef.onmessage = (event: MessageEvent) => {
          const {
            type,
            chunk,
            index,
            totalChunks: receivedTotalChunks,
            error,
          } = event.data;

          if (type === 'fileChunk') {
            chunks[index] = chunk; // Save chunk at the correct index
            if (chunks.length === receivedTotalChunks) {
              // All chunks received
              const totalLength = chunks.reduce(
                (sum, chunk) => sum + (chunk ? chunk.length : 0),
                0,
              );
              const fullArray = new Uint8Array(totalLength);
              let offset = 0;
              chunks.forEach(chunk => {
                if (chunk) {
                  fullArray.set(chunk, offset);
                  offset += chunk.length;
                }
              });
              resolve(fullArray);
            }
          } else if (type === 'fileCreated') {
            // Not used here as chunks should complete before this message
          } else if (type === 'error') {
            reject(new Error(error));
          }
        };

        workRef.postMessage({
          type: 'createFile',
          buffers,
          fileNames,
        });
      } else {
        reject(new Error('Worker not available'));
      }
    });
  }

  /**
   * Creates a downloadable file containing the serialized data using a web worker.
   *
   * This function sends the serialized buffers and corresponding filenames to the web worker.
   * The worker processes the data and sends back the file chunks. The function assembles the chunks
   * and creates a Blob object for download.
   *
   * @param {CryptoContextBuffers} buffers - The object containing all serialized buffers.
   * @param {FileNames} fileNames - The object containing filenames for all serialized data.
   * @param {Worker} workRef - The web worker reference.
   * @returns {Promise<void>} - A promise resolving to the downloaded file data.
   * @throws {Error} - If the web worker is not available or an error occurs during download creation.
   */
  async downloadFileViaWorker(
    workRef: Worker,
    fileName: string,
  ): Promise<void> {
    try {
      const byteArray = await this.createDownloadableFileViaWorker(
        this.buffers,
        this.getFileNames(),
        workRef,
      );

      // Create a blob and initiate download
      const blob = new Blob([byteArray], {type: 'application/zip'});
      saveAs(blob, fileName);
      // const url = URL.createObjectURL(blob);
      // const a = document.createElement('a');
      // a.href = url;
      // a.download = 'crypto_context.zip'; // Set the filename dynamically here
      // if needed a.click(); URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error creating downloadable file:', error);
      throw new Error('Error creating downloadable');
    }
  }

  /**
   * Creates a downloadable file containing the serialized data.
   *
   * This function generates a ZIP archive containing all serialized buffers
   * and writes them to the file. It then returns the created file in the specified
   * format (e.g., 'blob' for downloading).
   *
   * @param {JSZip.OutputType} [fileType] - The desired output file type (default: 'blob').
   * @returns {Promise<any>} - A promise resolving to the created file in the specified format.
   */
  async createDownloadableFile(
    fileType: JSZip.OutputType = 'blob',
  ): Promise<any> {
    const zip = new JSZip();

    const addBufferToZip = (buffer: Buffer | null, fileName: string) => {
      if (buffer && fileName) {
        zip.file(fileName, buffer);
      }
    };

    addBufferToZip(this.buffers.cryptoContextBuffer, this.cryptoContextFile);
    addBufferToZip(this.buffers.publicKeyBuffer, this.pubKeyFile);
    addBufferToZip(this.buffers.secretKeyBuffer, this.secretKeyFile);
    addBufferToZip(this.buffers.evalMultKeyBuffer, this.multKeyFile);
    addBufferToZip(this.buffers.automorphismKeyBuffer, this.rotKeyFile);
    addBufferToZip(
      this.buffers.FHEWtoCKKSSwitchKeyBuffer,
      this.FHEWtoCKKSSwitchKeyFile,
    );
    addBufferToZip(
      this.buffers.binfheCryptoContextBuffer,
      this.binFHECryptoContextFile,
    );
    addBufferToZip(
      this.buffers.binFHEBootRefreshKeyBuffer,
      this.binFHEBootRefreshKeyFile,
    );
    addBufferToZip(
      this.buffers.binFHEBootRotKeyBuffer,
      this.binFHEBootRotKeyFile,
    );
    addBufferToZip(this.buffers.keyIndexBuffer, this.keyIndexFile);

    this.buffers.EvalKeyMappings.forEach((mapping, _) => {
      const key = Object.keys(mapping)[0];
      const thekey = mapping[Number(key)];
      if (thekey) {
        zip.file(`${key}_${this.baseRefreshKeyFile}`, thekey.BSkey);
        zip.file(`${key}_${this.baseSwitchingKeyFile}`, thekey.KSkey);
      }
    });

    return zip.generateAsync({type: fileType});
  }

  /**
   * Initiates the download of the serialized data as a ZIP file.
   *
   * This function calls `createDownloadableFile` to generate the ZIP file
   * and then uses the `saveAs` function to initiate the download.
   *
   * @returns {Promise<void>} - A promise that resolves when the download is complete.
   */
  async downloadFile(fileName: string): Promise<void> {
    try {
      const blob: Blob = await this.createDownloadableFile();
      saveAs(blob, fileName);
    } catch (error) {
      console.error('Error creating downloadable file:', error);
    }
  }

  /**
   * Uploads a file containing serialized data and extracts the buffers.
   *
   * This function reads the contents of the uploaded file, loads it as a ZIP archive,
   * and extracts the serialized buffers from the ZIP. It then updates the internal buffers
   * of this class.
   *
   * @param {File} file - The uploaded file containing the serialized data.
   * @returns {Promise<void>} - A promise that resolves when the upload and extraction are complete.
   */
  async uploadFile(file: File): Promise<void> {
    const zip = new JSZip();
    const zipContent = await file.arrayBuffer(); // Read file content as ArrayBuffer
    await zip.loadAsync(zipContent);

    const readFileFromZip = async (
      fileName: string,
    ): Promise<Buffer | null> => {
      try {
        const content = await zip.file(fileName)?.async('nodebuffer');
        return content || null;
      } catch {
        return null;
      }
    };

    this.buffers.cryptoContextBuffer = await readFileFromZip(
      this.cryptoContextFile,
    );
    this.buffers.publicKeyBuffer = await readFileFromZip(this.pubKeyFile);
    this.buffers.evalMultKeyBuffer = await readFileFromZip(this.multKeyFile);
    this.buffers.automorphismKeyBuffer = await readFileFromZip(this.rotKeyFile);
    this.buffers.FHEWtoCKKSSwitchKeyBuffer = await readFileFromZip(
      this.FHEWtoCKKSSwitchKeyFile,
    );
    this.buffers.binfheCryptoContextBuffer = await readFileFromZip(
      this.binFHECryptoContextFile,
    );
    this.buffers.binFHEBootRefreshKeyBuffer = await readFileFromZip(
      this.binFHEBootRefreshKeyFile,
    );
    this.buffers.binFHEBootRotKeyBuffer = await readFileFromZip(
      this.binFHEBootRotKeyFile,
    );
    this.buffers.keyIndexBuffer = await readFileFromZip(this.keyIndexFile);
  }
}
/**
 * Class responsible for deserializing openFHE CryptoContext and keys data from a file.
 *
 * This class inherits from `DataAndLocation` and provides functionalities for
 * deserializing cryptographic contexts, keys, and other related data used in
 * CryptoContext, keys homomorphic encryption from a serialized file.
 */
export class SchemeSwitchingDataDeserializer extends DataAndLocation {
  /**
   * Serialization type used for the data (implementation specific).
   */
  SERTYPE: any; // Adjust based on the actual serialization type

  /**
   * Constructor for the class.
   *
   * @param {any} module - The openFHE WebAssembly module used for deserialization.
   */
  constructor(module: any) {
    super();
    this.module = module;
  }

  /**
   * Deserializes cryptocontext and keys data from a file.
   *
   * This function loads the file as a ZIP archive, extracts the serialized data,
   * and deserializes it using the provided openFHE WebAssembly module. It populates the
   * `cryptoContext`, `publicKey`, `secretKey`, and other relevant properties of
   * the class.
   *
   * @param {File} file - The file containing the serialized data.
   * @throws {Error} - If there are errors during deserialization or file handling.
   */
  async deserialize(file: File) {
    try {
      const zip = new JSZip();

      // Convert File to ArrayBuffer
      const arrayBuffer = await file.arrayBuffer();
      const unzippedFiles = await zip.loadAsync(arrayBuffer);

      const deserializeFile = async (
        filename: string,
        deserializeFunc: (arg0: ArrayBuffer, arg1: any) => any,
      ) => {
        console.debug('deserializeFile', filename);
        const file = unzippedFiles.file(filename);
        if (!file) {
          throw new Error(`File ${filename} not found in the zip`);
        }

        const fileData = await file.async('nodebuffer');
        const success = deserializeFunc(fileData, this.SERTYPE);
        if (!success) {
          throw new Error(`Error deserializing from ${filename}`);
        }
        return success;
      };

      // Deserialize crypto context
      const ccFileLoc = `${this.cryptoContextFile}`;
      this.cryptoContext = await deserializeFile(
        ccFileLoc,
        this.module.DeserializeCryptoContextFromBuffer,
      );

      // Deserialize public key
      const pubKeyFileLoc = `${this.pubKeyFile}`;
      this.publicKey = await deserializeFile(
        pubKeyFileLoc,
        this.module.DeserializePublicKeyFromBuffer,
      );

      // Deserialize Secret key
      const secretKeyFileLoc = `${this.secretKeyFile}`;
      this.secretKey = await deserializeFile(
        secretKeyFileLoc,
        this.module.DeserializePrivateKeyFromBuffer,
      );

      // Deserialize eval mult key
      const multKeyFileLoc = `${this.multKeyFile}`;
      const multKeyFile = unzippedFiles.file(multKeyFileLoc);
      if (multKeyFile) {
        const multKeyBuffer = await multKeyFile.async('nodebuffer');
        this.cryptoContext.DeserializeEvalMultKeyFromBuffer(
          multKeyBuffer,
          this.SERTYPE,
        );
      }

      // Deserialize automorphism key (rotation key)
      const rotKeyFileLoc = `${this.rotKeyFile}`;
      const rotKeyFile = unzippedFiles.file(rotKeyFileLoc);
      if (rotKeyFile) {
        const rotKeyBuffer = await rotKeyFile.async('nodebuffer');
        this.cryptoContext.DeserializeEvalAutomorphismKeyFromBuffer(
          rotKeyBuffer,
          this.SERTYPE,
        );
      }

      // Deserialize FHEW to CKKS switching key
      const FHEWtoCKKSSwitchKeyLoc = `${this.FHEWtoCKKSSwitchKeyFile}`;
      this.FHEWtoCKKSSwitchKey = await deserializeFile(
        FHEWtoCKKSSwitchKeyLoc,
        this.module.DeserializeSwkFC,
      );
      this.cryptoContext.SetSwkFC(this.FHEWtoCKKSSwitchKey);

      // Deserialize binFHECryptoContext
      const binFHECryptoContextFileLoc = `${this.binFHECryptoContextFile}`;
      this.binFHECryptoContext = await deserializeFile(
        binFHECryptoContextFileLoc,
        this.module.DeserializeBinFHECryptoContextFromBuffer,
      );

      // Deserialize boot refresh key
      const binFHEBootRefreshKeyFileLoc = `${this.binFHEBootRefreshKeyFile}`;
      const BTKey = new this.module.RingGSWBTKey();
      BTKey.BSkey = await deserializeFile(
        binFHEBootRefreshKeyFileLoc,
        this.module.DeserializeBinFHERefreshKeyFromBuffer,
      );

      // Deserialize boot rotation key
      const binFHEBootRotKeyFileLoc = `${this.binFHEBootRotKeyFile}`;
      BTKey.KSkey = await deserializeFile(
        binFHEBootRotKeyFileLoc,
        this.module.DeserializeBinFHESwitchingKeyFromBuffer,
      );

      this.binFHECryptoContext.BTKeyLoad(BTKey);

      // Deserialize key indices and associated keys
      const keyIndexFileLoc = `${this.keyIndexFile}`;
      let indices = await deserializeFile(
        keyIndexFileLoc,
        this.module.DeserializeSeedSeqVector,
      );
      indices = this.copyVecToJs(indices); // Assuming a helper function to copy to JS array
      if (indices.length === 0) {
        throw new Error(
          `Error deserializing from ${keyIndexFileLoc}. No indices found.`,
        );
      }

      // Deserialize refresh and switching keys for each index
      for (const index of indices) {
        const theKey = new this.module.RingGSWBTKey();

        const bsKeyFileName = this.createMapFileNameDeserialize(
          index,
          this.baseRefreshKeyFile,
        );
        theKey.BSkey = await deserializeFile(
          bsKeyFileName,
          this.module.DeserializeBinFHERefreshKeyFromBuffer,
        );

        const ksKeyFileName = this.createMapFileNameDeserialize(
          index,
          this.baseSwitchingKeyFile,
        );
        theKey.KSkey = await deserializeFile(
          ksKeyFileName,
          this.module.DeserializeBinFHESwitchingKeyFromBuffer,
        );

        this.binFHECryptoContext.BTKeyMapLoadSingleElement(index, theKey);
      }

      this.cryptoContext.SetBinCCForSchemeSwitch(this.binFHECryptoContext);
    } catch (error) {
      const msg =
        typeof error === 'number'
          ? this.module.getExceptionMessage(error)
          : error;
      throw new Error(msg);
    }
  }

  /**
   * Creates a filename for a key mapping based on an index and a base filename.
   *
   * @param {any} index - The index of the key mapping.
   * @param {string} baseFileName - The base filename for the key mapping file.
   * @returns {string} - The generated filename for the key mapping.
   */
  createMapFileNameDeserialize(index: any, baseFileName: string): string {
    return `${index}_${baseFileName}`;
  }

  /**
   * Helper function to convert a OpenFHE WebAssembly vector to a JavaScript array.
   *
   * @param {any} vec - The OpenFHE WebAssembly vector to be converted.
   * @returns {any[]} - A JavaScript array containing the elements of the vector.
   */
  copyVecToJs(vec: {size: () => number; get: (arg0: number) => any}): any[] {
    const result = [];
    for (let i = 0; i < vec.size(); i++) {
      result.push(vec.get(i));
    }
    return result;
  }

  async deserializeInBackend(fs: any) {
    try {
      const deserializeFile = async (
        filePath: string,
        deserializeFunc: (arg0: any, arg1: any) => any,
      ) => {
        const buffer = await fs.promises.readFile(filePath);
        const success = deserializeFunc(buffer, this.SERTYPE);
        if (!success) {
          throw new Error(`Error deserializing from ${filePath}`);
        }
        return success;
      };

      const ccFileLoc = `${this.dataDirectory}/${this.cryptoContextFile}`;
      this.cryptoContext = await deserializeFile(
        ccFileLoc,
        this.module.DeserializeCryptoContextFromBuffer,
      );

      const pubKeyFileLoc = `${this.dataDirectory}/${this.pubKeyFile}`;
      this.publicKey = await deserializeFile(
        pubKeyFileLoc,
        this.module.DeserializePublicKeyFromBuffer,
      );

      const secretKeyFileLoc = `${this.dataDirectory}/${this.secretKeyFile}`;
      this.secretKey = await deserializeFile(
        secretKeyFileLoc,
        this.module.DeserializePrivateKeyFromBuffer,
      );

      // const multKeyFileLoc = `${this.dataDirectory}/${this.multKeyFile}`;
      // try {
      //   const multKeybuffer = await fs.promises.readFile(multKeyFileLoc);
      //   this.cryptoContext.DeserializeEvalMultKeyFromBuffer(multKeybuffer, this.SERTYPE);
      // } catch {
      //   throw new Error(`Error deserializing from ${multKeyFileLoc}`);
      // }

      // const rotKeyFileLoc = `${this.dataDirectory}/${this.rotKeyFile}`;
      // try {
      //   const rotKeyFilebuffer = await fs.promises.readFile(rotKeyFileLoc);
      //   this.cryptoContext.DeserializeEvalAutomorphismKeyFromBuffer(rotKeyFilebuffer, this.SERTYPE);
      // } catch {
      //   throw new Error(`Error deserializing from ${rotKeyFileLoc}`);
      // }

      // const FHEWtoCKKSSwitchKeyLoc = `${this.dataDirectory}/${this.FHEWtoCKKSSwitchKeyFile}`;
      // this.FHEWtoCKKSSwitchKey = await deserializeFile(FHEWtoCKKSSwitchKeyLoc, this.module.DeserializeSwkFC);
      // this.cryptoContext.SetSwkFC(this.FHEWtoCKKSSwitchKey);

      // const binFHECryptoContextFileLoc = `${this.dataDirectory}/${this.binFHECryptoContextFile}`;
      // this.binFHECryptoContext = await deserializeFile(binFHECryptoContextFileLoc, this.module.DeserializeBinFHECryptoContextFromBuffer);

      // const binFHEBootRefreshKeyFileLoc = `${this.dataDirectory}/${this.binFHEBootRefreshKeyFile}`;
      // const BTKey = new this.module.RingGSWBTKey();
      // BTKey.BSkey = await deserializeFile(binFHEBootRefreshKeyFileLoc, this.module.DeserializeBinFHERefreshKeyFromBuffer);

      // const binFHEBootRotKeyFileLoc = `${this.dataDirectory}/${this.binFHEBootRotKeyFile}`;

      // BTKey.KSkey = await deserializeFile(binFHEBootRotKeyFileLoc, this.module.DeserializeBinFHESwitchingKeyFromBuffer);

      // this.binFHECryptoContext.BTKeyLoad(BTKey);

      // const keyIndexFileLoc = `${this.dataDirectory}/${this.keyIndexFile}`;
      // let indices = await deserializeFile(keyIndexFileLoc, this.module.DeserializeSeedSeqVector);
      // indices = this.copyVecToJs(indices);
      // if (indices.length === 0) {
      //   throw new Error(`Error deserializing from ${keyIndexFileLoc}. No indices found.`);
      // }

      // for (const index of indices) {
      //   const thekey = new this.module.RingGSWBTKey();

      //   const bskeyFileName = this.createMapFileName(index, this.baseRefreshKeyFile);
      //   thekey.BSkey = await deserializeFile(bskeyFileName, this.module.DeserializeBinFHERefreshKeyFromBuffer);

      //   const kskeyFileName = this.createMapFileName(index, this.baseSwitchingKeyFile);
      //   thekey.KSkey = await deserializeFile(kskeyFileName, this.module.DeserializeBinFHESwitchingKeyFromBuffer);

      //   this.binFHECryptoContext.BTKeyMapLoadSingleElement(index, thekey);
      // }

      // this.cryptoContext.SetBinCCForSchemeSwitch(this.binFHECryptoContext);
    } catch (error) {
      const msg =
        typeof error === 'number'
          ? this.module.getExceptionMessage(error)
          : error;
      throw new Error(msg);
    }
  }
}
