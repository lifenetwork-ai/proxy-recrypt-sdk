import { PreClient } from "./pre";
import {
  KeyPair,
  SecretKey,
  FirstLevelSymmetricKey,
  SecondLevelEncryptionResponse,
} from "./types";
import { splitSecret } from "./shamir";
import { generateRandomScalar } from "./utils/keypair";
import { EncryptionError, ValidationError } from "./errors";

export interface IPreClient {
  // Generate a random secret key, then split it into n shares
  generateKeys(): Promise<Array<Uint8Array>>;
  encryptData(
    secret: SecretKey,
    data: Uint8Array
  ): Promise<SecondLevelEncryptionResponse>;
  decryptData(
    encryptedKey: FirstLevelSymmetricKey,
    encryptedData: Uint8Array,
    secret: SecretKey
  ): Promise<Uint8Array>;
}

export interface IKeySplitter {
  generateShares(): Promise<Array<Uint8Array>>;
}

export class PreSdk implements IPreClient, IKeySplitter {
  preClient: PreClient;

  /// Paramteter for KeySplitter
  shareCount: number = 3; // number of shares
  threshold: number = 2; // minimum number of shares needed to reconstruct the secret

  constructor() {
    this.preClient = new PreClient();
  }

  /**
   * Generate a random key pair(public and secret key) in the BN254 curve
   *
   * @returns {KeyPair} A random key pair
   */
  generateRandomKeyPair(): KeyPair {
    const keyPair = this.preClient.generateRandomKeyPair();
    return keyPair;
  }

  /**
   * @deprecated This method is deprecated and will be removed in future versions. Use generateShares instead
   * Generate a random secret key, then split it into n shares
   * @returns {Promise<Array<Uint8Array>>} An array of Uint8Array shares
   * @throws {Error} If the key generation fails
   */
  async generateKeys(): Promise<Array<Uint8Array>> {
    const secretKey = this.preClient.generateRandomKeyPair().secretKey;
    const bytes = secretKey.toBytes();
    const shares = await splitSecret(bytes, 2, 3);
    return shares;
  }
  /**
   * Generates a random secret key and splits it into three shares:
   * - Share 1: Should be stored locally by the client
   * - Share 2: Should be stored in the data manager service
   * - Share 3: Should be stored as a recovery share (backup)
   *
   * @returns {Promise<Array<Uint8Array>>} An array of three Uint8Array shares in order:
   *   [localShare, dataManagerShare, recoveryShare]
   * @throws {Error} If the key generation or share splitting fails
   *
   * @example
   * const [localShare, dataManagerShare, recoveryShare] = await generateShares();
   * // Store localShare in local storage
   * // Send dataManagerShare to data manager service
   * // Backup recoveryShare securely
   */
  async generateShares(): Promise<Array<Uint8Array>> {
    const secretKey = this.preClient.generateRandomKeyPair().secretKey;
    const bytes = secretKey.toBytes();

    // Split into exactly 3 shares with a threshold of 2
    const shares = await splitSecret(bytes, 2, 3);

    if (shares.length !== 3) {
      throw new Error("Failed to generate the required number of shares");
    }

    return shares;
  }
  /**
   * Encrypts the data using the secret key. Each time this method is called,
   * a new random scalar (for symmetrical encryption) is generated to ensure
   * that the encryption is unique.
   *
   * @param secret The secret key to encrypt the data with
   * @param data The data to encrypt - should be serialized form of sensitive data
   * @returns The encrypted data
   * @throws {ValidationError} If the file type is invalid or file size exceeds 10MB
   * @throws {EncryptionError} If encryption process fails
   */
  async encryptData(
    secret: SecretKey,
    data: Uint8Array
  ): Promise<SecondLevelEncryptionResponse> {
    try {
      // Validate the data first
      await this.preClient.validate(data);

      const randomScalar = generateRandomScalar();
      const encryptedData = await this.preClient.secondLevelEncryption(
        secret,
        data,
        randomScalar
      );

      return encryptedData;
    } catch (error) {
      // Handle validation errors from PreClient
      if (error instanceof Error) {
        if (
          error.message === "Invalid file type" ||
          error.message === "File size exceeds 10 MB"
        ) {
          throw new ValidationError(error.message);
        }

        // Any other error during encryption process
        throw new EncryptionError(`Encryption failed: ${error.message}`);
      }

      // Unexpected non-Error throws
      throw error;
    }
  }

  /**
   *
   * @param encryptedKey
   * @param encryptedData
   * @param secret
   * @returns
   */
  async decryptData(
    encryptedKey: FirstLevelSymmetricKey,
    encryptedData: Uint8Array,
    secret: SecretKey
  ): Promise<Uint8Array> {
    const decryptedData = await this.preClient.decryptFirstLevel(
      {
        encryptedKey,
        encryptedMessage: encryptedData,
      },
      secret
    );
    return decryptedData;
  }
}
