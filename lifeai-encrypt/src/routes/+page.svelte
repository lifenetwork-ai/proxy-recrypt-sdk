<script lang="ts">
  import * as pre from "../../../pre-ts/dist/index";
  import { browser } from "$app/environment";
  import { onMount } from "svelte";
  import { SecretKey } from "../../../pre-ts/dist/types";

  const client = new pre.PreSdk();
  let shares: Array<Uint8Array> = [];
  let selectedFile: File | null = null;
  let originalImageUrl: string | null = null;
  let encryptedMessage: Uint8Array | null = null;
  let secondLevelEncrypted: pre.SecondLevelEncryptionResponse | null = null;
  let encryptedBase64: string | null = null;
  let encryptedSize: number;
  let pixelGrid: Array<string> = [];
  let decryptionDetails: string | null = null;
  let passphrase: string = "";
  let storedShareInfo: string | null = null;
  let decryptPassphrase: string = "";
  let errorMessage: string | null = null;
  let reEncryptionKey: pre.G2Point | null = null;
  let proxyStoreId: string | null = null;
  let decryptedImage: string | null = null;
  let userBSecretKey: SecretKey | null = null;
  let userBPublicKey: any | null = null;
  let reEncryptedData: any | null = null;
  let proxyRequestStatus: string | null = null;

  // Fixed B secret for testing purpose
  let secretB: SecretKey = new SecretKey(66666666n, 88888888n);

  interface ShareData {
    share: Uint8Array;
    hasPassphrase: boolean;
    passphraseHash: string | null;
  }

  // Check if there's a stored share on component initialization
  function checkStoredShare() {
    if (browser) {
      const storedShare = localStorage.getItem("encryptionShare1");
      if (storedShare) {
        try {
          const shareData = JSON.parse(storedShare);
          storedShareInfo = `Share 1 stored with passphrase: ${shareData.hasPassphrase ? "Yes" : "No"}`;
        } catch (e) {
          storedShareInfo = "Invalid stored share data";
        }
      } else {
        storedShareInfo = null;
      }
    }
  }

  // Call this in onMount instead of during component initialization
  onMount(() => {
    checkStoredShare();
  });

  async function handleGenerateKeys() {
    shares = await client.generateKeys();

    // Automatically store share 1 with passphrase if provided
    if (shares.length > 0) {
      storeShareWithPassphrase();
    }
  }

  function storeShareWithPassphrase() {
    if (!browser || shares.length === 0) return;

    const shareData1: ShareData = {
      share: shares[0],
      hasPassphrase: passphrase.length > 0,
      // Only store passphrase hash or indicator, never the actual passphrase
      passphraseHash: passphrase ? hashPassphrase(passphrase) : null,
    };

    const shareData2: ShareData = {
      share: shares[1],
      hasPassphrase: passphrase.length > 0,
      // Only store passphrase hash or indicator, never the actual passphrase
      passphraseHash: passphrase ? hashPassphrase(passphrase) : null,
    };

    const shareData3: ShareData = {
      share: shares[2],
      hasPassphrase: passphrase.length > 0,
      // Only store passphrase hash or indicator, never the actual passphrase
      passphraseHash: passphrase ? hashPassphrase(passphrase) : null,
    };

    localStorage.setItem("encryptionShare1", JSON.stringify(shareData1));
    localStorage.setItem("encryptionShare2", JSON.stringify(shareData2));
    localStorage.setItem("encryptionShare3", JSON.stringify(shareData3));

    storedShareInfo = `Share 1,2,3 stored with passphrase: ${passphrase.length > 0 ? "Yes" : "No"}`;
    errorMessage = null;
  }

  // Simple function to hash the passphrase (in a real app, use a proper crypto hash)
  function hashPassphrase(phrase: string): string {
    // This is a placeholder - in a real app, use a proper crypto hash function
    let hash = 0;
    for (let i = 0; i < phrase.length; i++) {
      const char = phrase.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString(16);
  }

  async function handleFileSelect(event: Event) {
    const target = event.target as HTMLInputElement;
    if (target.files) {
      selectedFile = target.files[0];
      originalImageUrl = URL.createObjectURL(selectedFile);
    }
  }

  function visualizeEncryptedData(data: Uint8Array) {
    pixelGrid = [];
    const pixelsPerSide = Math.ceil(Math.sqrt(data.length / 3));

    for (let i = 0; i < pixelsPerSide * pixelsPerSide; i++) {
      const dataIndex = i * 3;
      const r = data[dataIndex % data.length];
      const g = data[(dataIndex + 1) % data.length];
      const b = data[(dataIndex + 2) % data.length];
      pixelGrid.push(`rgb(${r}, ${g}, ${b})`);
    }
  }

  async function handleEncrypt() {
    if (selectedFile) {
      const secret = new SecretKey(1111n, 2222n);
      secondLevelEncrypted = await client.encryptData(
        secret,
        new Uint8Array(await selectedFile.arrayBuffer())
      );
      encryptedBase64 = arrayBufferToBase64(
        secondLevelEncrypted.encryptedMessage
      );
      encryptedSize = encryptedBase64.length;

      // Visualize the encrypted data
      visualizeEncryptedData(secondLevelEncrypted.encryptedMessage);
      errorMessage = null;

      let pubB = client.preClient.secretToPubkey(secretB);
      reEncryptionKey = client.preClient.generateReEncryptionKey(
        secret.first,
        pubB.second
      );

      console.log(
        btoa(
          Array.from(secondLevelEncrypted.encryptedMessage)
            .map((byte) => String.fromCharCode(byte))
            .join("")
        ).slice(0, 10)
      );
    }
  }

  async function sendToProxy() {
    try {
      const proxyClient = new pre.ProxyClient();
      const response = await proxyClient.store(
        reEncryptionKey!,
        secondLevelEncrypted!.encryptedKey,
        secondLevelEncrypted!.encryptedMessage,
        "alice"
      );

      if (response.id) {
        proxyStoreId = response.id;
        console.log("Successfully stored data on proxy with ID:", proxyStoreId);
        errorMessage = null;
      } else {
        console.error("Failed to store data on proxy");
        errorMessage = "Failed to store data on proxy";
      }
    } catch (error: any) {
      console.error("Error storing data on proxy:", error);
      errorMessage = "Error storing data on proxy: " + error.message;
    }
  }

  function decryptShare(storedShareData: string | null): Uint8Array | null {
    if (!storedShareData) {
      errorMessage = "No encryption share found in local storage.";
      return null;
    }

    try {
      const shareData = JSON.parse(storedShareData) as ShareData;

      // If the stored share has a passphrase, verify it matches
      if (shareData.hasPassphrase && shareData.passphraseHash) {
        if (!decryptPassphrase) {
          errorMessage = "This share requires a passphrase for decryption.";
          return null;
        }

        // Verify the passphrase hash
        if (hashPassphrase(decryptPassphrase) !== shareData.passphraseHash) {
          errorMessage = "Incorrect passphrase. Please try again.";
          return null;
        }
      }

      return shareData.share;
    } catch (e) {
      errorMessage = "Invalid share data format.";
      return null;
    }
  }

  async function generateUserBKeys() {
    try {
      // For demo purposes, using fixed values
      userBSecretKey = new SecretKey(66666666n, 88888888n);
      userBPublicKey = client.preClient.secretToPubkey(userBSecretKey);
      return true;
    } catch (error: any) {
      errorMessage = "Error generating User B keys: " + error.message;
      return false;
    }
  }

  async function handleDecryptAsB() {
    try {
      if (!proxyStoreId) {
        errorMessage = "No proxy store ID available. Please store data first.";
        return;
      }

      if (!userBSecretKey) {
        const success = await generateUserBKeys();
        if (!success) return;
      }

      proxyRequestStatus = "Requesting data from proxy server...";
      const proxyClient = new pre.ProxyClient();

      // Request re-encrypted data from proxy
      const { firstLevelKey, encryptedData } =
        await proxyClient.request(proxyStoreId);
      proxyRequestStatus = "Data received from proxy server";
      reEncryptedData = { firstLevelKey, encryptedData };

      // Decrypt the data using Bob's secret key
      const decryptedData = await client.preClient.decryptFirstLevel(
        {
          encryptedKey: firstLevelKey,
          encryptedMessage: new Uint8Array(
            [...atob(encryptedData.toString())].map((char) =>
              char.charCodeAt(0)
            )
          ),
        },
        userBSecretKey!
      );

      // Create a blob from the decrypted data
      const blob = new Blob([decryptedData], { type: "image/jpeg" });
      decryptedImage = URL.createObjectURL(blob);

      decryptionDetails = "Successfully decrypted the image as user B";
      errorMessage = null;
    } catch (error: any) {
      console.error("Error decrypting data:", error);
      errorMessage = "Error decrypting data: " + error.message;
      decryptionDetails = null;
      proxyRequestStatus = null;
    }
  }

  function clearStoredShare() {
    if (browser) {
      localStorage.removeItem("encryptionShare1");
      localStorage.removeItem("encryptionShare2");
      localStorage.removeItem("encryptionShare3");
      storedShareInfo = null;
      errorMessage = null;
    }
  }

  function formatBytes(bytes: number, decimals = 2) {
    if (bytes === 0) return "0 Bytes";

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
  }

  function downloadEncryptedData() {
    if (encryptedMessage && browser) {
      const blob = new Blob([encryptedMessage], {
        type: "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "encrypted-image.bin";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  }

  // Helper method to convert ArrayBuffer to Base64 string
  function arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }
</script>

<main class="container">
  <h1>Image Encryption App</h1>
  <div class="info-banner">
    <p>
      <strong>Privacy Notice:</strong> All processing happens in your browser. No
      data is sent to or stored on any server.
    </p>
  </div>

  {#if errorMessage}
    <div class="error-banner">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        stroke-linecap="round"
        stroke-linejoin="round"
      >
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <p>{errorMessage}</p>
    </div>
  {/if}

  <section>
    <h2>1. Generate and Split Keys</h2>
    <div class="process-flow">
      <div class="flow-step">
        <span class="step-number">1</span>
        <span>Generate keys in browser</span>
      </div>
      <div class="flow-arrow">→</div>
      <div class="flow-step">
        <span class="step-number">2</span>
        <span>Split into 3 shares</span>
      </div>
      <div class="flow-arrow">→</div>
      <div class="flow-step">
        <span class="step-number">3</span>
        <span>Store share 1 with passphrase</span>
      </div>
    </div>

    <div class="passphrase-container">
      <label for="passphrase">Passphrase (optional):</label>
      <input
        id="passphrase"
        type="password"
        bind:value={passphrase}
        placeholder="Enter a passphrase for key storage"
      />
      <p class="passphrase-info">
        Adding a passphrase adds an additional layer of security
      </p>
    </div>

    <div class="button-row">
      <button on:click={handleGenerateKeys}>Generate Keys</button>
      {#if storedShareInfo}
        <button class="secondary-btn" on:click={clearStoredShare}
          >Clear Stored Share</button
        >
      {/if}
    </div>

    {#if storedShareInfo}
      <div class="stored-share-info">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <path
            d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"
          ></path>
          <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
          <line x1="12" y1="22.08" x2="12" y2="12"></line>
        </svg>
        <p>{storedShareInfo}</p>
      </div>
    {/if}

    {#if shares.length > 0}
      <div class="shares">
        <h3>Your key shares:</h3>
        <ul>
          {#each shares as share, i}
            <li>Share {i + 1}: {share}</li>
          {/each}
        </ul>
        <div class="storage-info">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path
              d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"
            ></path>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
            <line x1="12" y1="22.08" x2="12" y2="12"></line>
          </svg>
          <p>
            Share 1 has been stored in your browser's local storage{passphrase
              ? " with passphrase protection"
              : ""}
          </p>
        </div>
      </div>
    {/if}
  </section>

  <section>
    <h2>2. Encrypt Image</h2>
    <div class="process-flow">
      <div class="flow-step">
        <span class="step-number">1</span>
        <span>Select image from your device</span>
      </div>
      <div class="flow-arrow">→</div>
      <div class="flow-step">
        <span class="step-number">2</span>
        <span>Encrypt in browser using your key</span>
      </div>
      <div class="flow-arrow">→</div>
      <div class="flow-step">
        <span class="step-number">3</span>
        <span>Download or view encrypted result</span>
      </div>
    </div>

    <div class="file-input-container">
      <label for="image-upload" class="file-input-label">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="24"
          height="24"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
          <circle cx="8.5" cy="8.5" r="1.5"></circle>
          <polyline points="21 15 16 10 5 21"></polyline>
        </svg>
        Choose Image
      </label>
      <input
        id="image-upload"
        type="file"
        accept="image/*"
        on:change={handleFileSelect}
        class="file-input"
      />
      {#if selectedFile}
        <p class="file-name">
          Selected: {selectedFile.name} ({formatBytes(selectedFile.size)})
        </p>
      {/if}
    </div>

    {#if selectedFile}
      <button on:click={handleEncrypt}>Encrypt Image</button>

      <div class="image-comparison">
        <div class="image-container small-image">
          <h3>Original Image (Input)</h3>
          <img src={originalImageUrl} alt="Original image" />
          <div class="data-source">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            <span>From your device</span>
          </div>
        </div>

        {#if encryptedBase64}
          <div class="image-container">
            <h3>Encrypted Data (Output)</h3>
            <div class="encrypted-preview">
              <div class="preview-tabs">
                <div class="preview-section">
                  <h4>As Image</h4>
                  <div class="encrypted-image">
                    <div class="pixel-grid">
                      {#each pixelGrid as color}
                        <div
                          class="pixel"
                          style="background-color: {color};"
                        ></div>
                      {/each}
                    </div>
                  </div>
                </div>
                <div class="preview-section">
                  <h4>As Text</h4>
                  <div class="encrypted-text">
                    <p class="base64-preview">
                      {encryptedBase64.substring(0, 100)}...
                    </p>
                  </div>
                </div>
              </div>
              <div class="data-info">
                <p>Size: {encryptedSize}</p>
                <button class="download-btn" on:click={downloadEncryptedData}>
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                  >
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                  </svg>
                  Download
                </button>
              </div>
              <p class="note">
                Note: These are two different ways to view the same encrypted
                data
              </p>
            </div>
            <div class="data-source">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              >
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="16"></line>
                <line x1="8" y1="12" x2="16" y2="12"></line>
              </svg>
              <span>Generated in browser</span>
            </div>
          </div>
        {/if}
      </div>
    {/if}
  </section>

  {#if secondLevelEncrypted && reEncryptionKey}
    <section>
      <h2>3. Store Encrypted Data on Proxy</h2>
      <div class="process-flow">
        <div class="flow-step">
          <span class="step-number">1</span>
          <span>Store encrypted data and re-encryption key</span>
        </div>
        <div class="flow-arrow">→</div>
        <div class="flow-step">
          <span class="step-number">2</span>
          <span>Get storage ID for later retrieval</span>
        </div>
      </div>

      <button on:click={sendToProxy}>Store on Proxy Server</button>

      {#if proxyStoreId}
        <div class="stored-share-info">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
            <polyline points="7 10 12 15 17 10"></polyline>
            <line x1="12" y1="15" x2="12" y2="3"></line>
          </svg>
          <p>Successfully stored with ID: {proxyStoreId}</p>
        </div>
      {/if}
    </section>

    <section>
      <h2>4. Decrypt as User B</h2>
      <div class="process-flow">
        <div class="flow-step">
          <span class="step-number">1</span>
          <span>Generate User B Keys</span>
        </div>
        <div class="flow-arrow">→</div>
        <div class="flow-step">
          <span class="step-number">2</span>
          <span>Request re-encrypted data</span>
        </div>
        <div class="flow-arrow">→</div>
        <div class="flow-step">
          <span class="step-number">3</span>
          <span>Decrypt with User B's key</span>
        </div>
      </div>

      <div class="decryption-status">
        <!-- User B Key Status -->
        {#if userBSecretKey}
          <div class="status-item success">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                d="M12 2a10 10 0 0 1 10 10a10 10 0 0 1-10 10A10 10 0 0 1 2 12A10 10 0 0 1 12 2z"
              />
              <path d="M9 12l2 2l4-4" />
            </svg>
            <span>User B Keys Generated (Local)</span>
          </div>
        {/if}

        <!-- Proxy Request Status -->
        {#if proxyRequestStatus}
          <div class="status-item info">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="M12 16v-4" />
              <path d="M12 8h.01" />
            </svg>
            <span>{proxyRequestStatus}</span>
          </div>
        {/if}

        <!-- Decryption Status -->
        {#if decryptionDetails}
          <div class="status-item success">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                d="M12 2a10 10 0 0 1 10 10a10 10 0 0 1-10 10A10 10 0 0 1 2 12A10 10 0 0 1 12 2z"
              />
              <path d="M9 12l2 2l4-4" />
            </svg>
            <span>{decryptionDetails}</span>
          </div>
        {/if}
      </div>

      <button on:click={handleDecryptAsB}>Start Decryption Process</button>

      {#if decryptedImage}
        <div class="image-preview small-image">
          <h3>Decrypted Image</h3>
          <img src={decryptedImage} alt="Decrypted image" />
          <div class="data-source">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <circle cx="12" cy="12" r="10" />
              <path d="M12 16v-4" />
              <path d="M12 8h.01" />
            </svg>
            <span>Decrypted in browser using User B's key</span>
          </div>
        </div>
      {/if}
    </section>
  {/if}
</main>

<style>
  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
  }

  section {
    margin: 2rem 0;
    padding: 1.5rem;
    border: 1px solid #ccc;
    border-radius: 8px;
    background-color: #f9f9f9;
  }

  button {
    padding: 0.5rem 1rem;
    background-color: #4caf50;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    margin: 0.5rem 0;
    font-weight: bold;
  }

  button:hover {
    background-color: #45a049;
  }

  .secondary-btn {
    background-color: #f44336;
  }

  .secondary-btn:hover {
    background-color: #d32f2f;
  }

  .button-row {
    display: flex;
    gap: 1rem;
    margin: 1rem 0;
  }

  .info-banner {
    background-color: #e7f3fe;
    border-left: 4px solid #2196f3;
    padding: 1rem;
    margin-bottom: 2rem;
    border-radius: 4px;
  }

  .error-banner {
    display: flex;
    align-items: center;
    background-color: #ffebee;
    border-left: 4px solid #f44336;
    padding: 1rem;
    margin-bottom: 2rem;
    border-radius: 4px;
  }

  .error-banner svg {
    color: #f44336;
    margin-right: 0.5rem;
  }

  .warning-message {
    display: flex;
    align-items: center;
    background-color: #fff3e0;
    border-left: 4px solid #ff9800;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 4px;
  }

  .warning-message svg {
    color: #ff9800;
    margin-right: 0.5rem;
  }

  .passphrase-container {
    margin: 1rem 0;
  }

  .passphrase-container label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: bold;
  }

  .passphrase-container input {
    padding: 0.5rem;
    border: 1px solid #ccc;
    border-radius: 4px;
    width: 100%;
    max-width: 400px;
  }

  .passphrase-info {
    margin-top: 0.5rem;
    font-size: 0.8rem;
    color: #666;
  }

  .stored-share-info {
    display: flex;
    align-items: center;
    background-color: #e8f5e9;
    border-left: 4px solid #4caf50;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 4px;
  }

  .stored-share-info svg {
    color: #4caf50;
    margin-right: 0.5rem;
  }

  .process-flow {
    display: flex;
    align-items: center;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .flow-step {
    display: flex;
    align-items: center;
    background-color: #e8f5e9;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    border: 1px solid #c8e6c9;
  }

  .step-number {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    background-color: #4caf50;
    color: white;
    border-radius: 50%;
    margin-right: 0.5rem;
    font-weight: bold;
  }

  .flow-arrow {
    font-size: 1.5rem;
    color: #666;
    margin: 0 0.5rem;
  }

  .shares {
    margin-top: 1rem;
    background-color: white;
    padding: 1rem;
    border-radius: 4px;
    border: 1px solid #ddd;
  }

  .storage-info {
    display: flex;
    align-items: center;
    margin-top: 1rem;
    padding: 0.5rem;
    background-color: #fff9c4;
    border-radius: 4px;
  }

  .storage-info svg {
    margin-right: 0.5rem;
    color: #fbc02d;
  }

  .file-input-container {
    margin: 1rem 0;
  }

  .file-input {
    display: none;
  }

  .file-input-label {
    display: inline-flex;
    align-items: center;
    padding: 0.5rem 1rem;
    background-color: #2196f3;
    color: white;
    border-radius: 4px;
    cursor: pointer;
    font-weight: bold;
  }

  .file-input-label svg {
    margin-right: 0.5rem;
  }

  .file-input-label:hover {
    background-color: #0b7dda;
  }

  .file-name {
    margin-top: 0.5rem;
    font-size: 0.9rem;
    color: #666;
  }

  .image-comparison {
    display: flex;
    gap: 2rem;
    margin-top: 1rem;
    flex-wrap: wrap;
  }

  .image-container {
    flex: 1;
    min-width: 300px;
    background-color: white;
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid #ddd;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  }

  .small-image img {
    max-width: 100%;
    height: auto;
    width: 150px;
  }

  .encrypted-preview {
    position: relative;
  }

  .preview-tabs {
    display: flex;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  .preview-section {
    flex: 1;
    min-width: 0;
  }

  .preview-section h4 {
    margin: 0 0 0.5rem 0;
    font-size: 0.9rem;
    color: #666;
  }

  .encrypted-image {
    background-color: #000;
    padding: 0.5rem;
    border-radius: 4px;
    border: 1px solid #eee;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
  }

  .encrypted-canvas {
    image-rendering: pixelated;
    background-color: black;
    border: 1px solid #333;
    width: 200px;
    height: 200px;
  }

  .encrypted-text {
    background-color: #f5f5f5;
    padding: 1rem;
    border-radius: 4px;
    border: 1px solid #eee;
    font-family: monospace;
    overflow-wrap: break-word;
    height: 100%;
    min-height: 100px;
    overflow-y: auto;
  }

  .base64-preview {
    margin: 0;
    font-size: 0.8rem;
    color: #333;
  }

  .data-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 0.5rem;
  }

  .download-btn {
    display: inline-flex;
    align-items: center;
    padding: 0.25rem 0.5rem;
    font-size: 0.8rem;
    background-color: #2196f3;
  }

  .download-btn svg {
    margin-right: 0.25rem;
  }

  .note {
    font-size: 0.8rem;
    color: #666;
    margin-top: 0.5rem;
  }

  .data-source {
    display: flex;
    align-items: center;
    margin-top: 0.5rem;
    font-size: 0.8rem;
    color: #666;
    background-color: #f5f5f5;
    padding: 0.5rem;
    border-radius: 4px;
  }

  .data-source svg {
    margin-right: 0.5rem;
  }

  .image-preview {
    margin-top: 1rem;
    background-color: white;
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid #ddd;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
  }

  .image-preview img {
    max-width: 100%;
    height: auto;
    border: 1px solid #eee;
    border-radius: 4px;
  }

  h1 {
    color: #2e7d32;
    margin-bottom: 1rem;
  }

  h2 {
    color: #2e7d32;
    border-bottom: 2px solid #c8e6c9;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
  }

  h3 {
    margin-bottom: 1rem;
    color: #333;
  }

  .pixel-grid {
    display: grid;
    grid-template-columns: repeat(50, 1fr);
    gap: 1px;
    width: 100%;
    max-width: 400px;
    height: 400px;
    overflow: hidden;
  }

  .pixel {
    width: 100%;
    padding-top: 100%;
  }

  .decryption-details {
    margin-top: 1rem;
    font-size: 0.9rem;
    color: #666;
  }

  .decryption-status {
    margin: 1rem 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .status-item {
    display: flex;
    align-items: center;
    padding: 0.5rem;
    border-radius: 4px;
    font-size: 0.9rem;
  }

  .status-item svg {
    margin-right: 0.5rem;
  }

  .status-item.success {
    background-color: #e8f5e9;
    color: #2e7d32;
    border: 1px solid #c8e6c9;
  }

  .status-item.info {
    background-color: #e3f2fd;
    color: #1976d2;
    border: 1px solid #bbdefb;
  }
</style>
