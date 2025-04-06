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
    let decryptionDetails: string | null = null;
    let passphrase: string = "";
    let storedShareInfo: string | null = null;
    let errorMessage: string | null = null;
    let reEncryptionKey: pre.G2Point | null = null;
    let proxyStoreId: string | null = null;
    let decryptedImage: string | null = null;
    let userBSecretKey: SecretKey | null = null;
    let userBPublicKey: any | null = null;
    let reEncryptedData: any | null = null;
    let proxyRequestStatus: string | null = null;
    let reconstructionStatus: string | null = null;
    let secretKeyDisplay: string | null = null;
    let generatedSecretKeyDisplay: string | null = null;
    let encryptPassphrase: string = "";
    let passphraseError: string | null = null;
    let reconstructionSteps: Array<string> = [];
    let decryptionSteps: Array<string> = [];

    let proxyClient =  new pre.ProxyClient(
                    "http://localhost:8080/api/v1/dataowner",
                    "5030a202-d52f-4a51-8d53-f776974f52ee",
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvcmdhbml6YXRpb25faWQiOiI1MDMwYTIwMi1kNTJmLTRhNTEtOGQ1My1mNzc2OTc0ZjUyZWUiLCJ1c2VyX2lkIjoiYjFlNmUzZjEtNzhkYS00ZTYzLTk5MWItNDRiMDY5OTg4YzdhIiwidXNlcl9uYW1lIjoiIiwiZXhwIjoxNzQzNjczNzQwfQ.88YWQd6fdLBaP-ruiOpJ7c2F6CTk1lVJW-9yjrUOShQ",
                );

    // Fixed B secret for testing purpose
    let secretB: SecretKey = new SecretKey(66666666n, 88888888n);

    interface ShareData {
        share: ArrayBuffer;
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
        try {
            shares = await client.generateKeys();

            // Convert shares to secret key and display it
            const secretBytes = await pre.combineSecret([shares[0], shares[1]]);
            const secret = SecretKey.fromBytes(secretBytes);
            generatedSecretKeyDisplay = `Generated Secret Key: (${secret.first}, ${secret.second})`;

            // Automatically store share 1 with passphrase if provided
            if (shares.length > 0) {
                storeShareWithPassphrase();
            }
        } catch (error: any) {
            errorMessage = "Error generating keys: " + error.message;
            generatedSecretKeyDisplay = null;
        }
    }

    async function storeShareWithPassphrase() {
        if (!browser || shares.length === 0) return;

        try {
            const passphraseHash = passphrase
                ? hashPassphrase(passphrase)
                : null;

                // Only store the first share on local
                const encryptedShare = passphrase
                    ? await encryptShare(shares[0], passphrase)
                    : shares[0].slice().buffer;

                const shareData: ShareData = {
                    share: encryptedShare,
                    hasPassphrase: passphrase.length > 0,
                    passphraseHash,
                };

                localStorage.setItem(
                    `encryptionShare${1}`,
                    JSON.stringify({
                        ...shareData,
                        share: Array.from(new Uint8Array(shareData.share)), // Convert to array for JSON
                    })
                );


                // Store the second share to the DAM
                const encryptedShare2 = passphrase
                    ? await encryptShare(shares[1], passphrase)
                    : shares[1].slice().buffer;

                const shareData2: ShareData = {
                    share: encryptedShare2,
                    hasPassphrase: passphrase.length > 0,
                    passphraseHash,
                };

                const secretBytes = await pre.combineSecret([shares[0], shares[1]]);
                const secret = SecretKey.fromBytes(secretBytes);

                const pubkeyA = client.preClient.secretToPubkey(secret)
                await proxyClient.uploadKey(
                    new Uint8Array(shareData2.share),
                    pubkeyA,
                );

                localStorage.setItem(
                    `encryptionShare${2}`,
                    JSON.stringify({
                        ...shareData2,
                        share: Array.from(new Uint8Array(shareData2.share)), // Convert to array for JSON
                    })
                );
            storedShareInfo = `Shares stored with passphrase: ${passphrase.length > 0 ? "Yes" : "No"}`;
            errorMessage = null;
        } catch (error: any) {
            errorMessage = "Error storing shares: " + error.message;
        }
    }

    function hashPassphrase(phrase: string): string {
        let hash = 0;
        for (let i = 0; i < phrase.length; i++) {
            const char = phrase.charCodeAt(i);
            hash = (hash << 5) - hash + char;
            hash = hash & hash;
        }
        return hash.toString(16);
    }

    function getShareFromLocalStorage(key: string): ShareData | null {
        if (browser) {
            const storedShare = localStorage.getItem(key);
            if (storedShare) {
                return JSON.parse(storedShare);
            }
        }
        return null;
    }

    async function handleFileSelect(event: Event) {
        const target = event.target as HTMLInputElement;
        if (target.files) {
            selectedFile = target.files[0];
            originalImageUrl = URL.createObjectURL(selectedFile);
        }
    }

    async function delay(ms: number) {
        return new Promise(resolve => setTimeout(resolve, ms / 5));
    }

    async function handleEncrypt() {
        if (selectedFile) {
            try {
                reconstructionSteps = []; // Clear previous steps
                passphraseError = null;
                
                reconstructionSteps = [...reconstructionSteps, "Retrieving key share 1 from storage..."];
                const share1 = getShareFromLocalStorage("encryptionShare1");
                await delay(1500); // 1.5 second delay
                
                reconstructionSteps = [...reconstructionSteps, "Retrieving key share 2 from storage..."];

                const share2 = getShareFromLocalStorage("encryptionShare2");
                await delay(1200); // 1.2 second delay

                if (!share1 || !share2) {
                    throw new Error("Required key shares not found in storage");
                }

                let share1Array: Uint8Array;
                let share2Array: Uint8Array;

                if (share1.hasPassphrase) {
                    reconstructionSteps = [...reconstructionSteps, "Decrypting key share 1 with passphrase..."];
                    if (!encryptPassphrase) {
                        passphraseError = "Please enter the passphrase used during key generation";
                        throw new Error(passphraseError);
                    }
                    if (hashPassphrase(encryptPassphrase) !== share1.passphraseHash) {
                        passphraseError = "Incorrect passphrase";
                        throw new Error(passphraseError);
                    }

                    share1Array = await decryptShare(
                        new Uint8Array(share1.share).buffer,
                        encryptPassphrase
                    );
                    await delay(800);
                    
                    reconstructionSteps = [...reconstructionSteps, "Decrypting key share 2 with passphrase..."];
                    share2Array = await decryptShare(
                        new Uint8Array(share2.share).buffer,
                        encryptPassphrase
                    );
                    await delay(1000);
                } else {
                    reconstructionSteps = [...reconstructionSteps, "Processing unencrypted key shares..."];
                    share1Array = new Uint8Array(share1.share);
                    share2Array = new Uint8Array(share2.share);

                const share2FromProxy = await proxyClient.getKeyShare()

                if (new Uint8Array(share2.share).toString() !== new Uint8Array(share2FromProxy).toString()) {
                    reconstructionSteps = [...reconstructionSteps, "Key share 2 mismatch!"];
                    console.error("Key share 2 mismatch!");
                    console.log("storage share 2", new Uint8Array(share2.share).toString());
                    console.log("proxy share 2", new Uint8Array(share2FromProxy).toString());
                    throw new Error("Key share 2 mismatch!");
                } else {
                    reconstructionSteps = [...reconstructionSteps, "Key shares verified successfully!"];
                }
                     
                    await delay(1000);
                }

                reconstructionSteps = [...reconstructionSteps, "Reconstructing secret key from shares..."];
                await delay(1500);
                const secretBytes = await pre.combineSecret([share1Array, share2Array]);

                reconstructionSteps = [...reconstructionSteps, "Generating secret key..."];
                await delay(800);
                const secret = SecretKey.fromBytes(secretBytes);
                secretKeyDisplay = `Secret Key: (${secret.first}, ${secret.second})`;

                reconstructionSteps = [...reconstructionSteps, "Encrypting data with secret key..."];
                await delay(2000);
                secondLevelEncrypted = await client.encryptData(
                    secret,
                    new Uint8Array(await selectedFile.arrayBuffer())
                );

                encryptedBase64 = arrayBufferToBase64(
                    secondLevelEncrypted.encryptedMessage
                );
                encryptedSize = secondLevelEncrypted.encryptedMessage.length;

                errorMessage = null;

                let pubB = client.preClient.secretToPubkey(secretB);
                reEncryptionKey = client.preClient.generateReEncryptionKey(
                    secret.first,
                    pubB.second
                );

                reconstructionSteps = [...reconstructionSteps, "Encryption complete!"];

                console.log(
                    btoa(
                        Array.from(secondLevelEncrypted.encryptedMessage)
                            .map((byte) => String.fromCharCode(byte))
                            .join("")
                    ).slice(0, 10)
                );
            } catch (error: any) {
                errorMessage = "Error during encryption: " + error.message;
                reconstructionStatus = null;
                secretKeyDisplay = null;
            }
        }
    }

    async function sendToProxy() {
        try {
            const response = await proxyClient.storeFile(
                secondLevelEncrypted!.encryptedMessage,
            );

            if (response.id) {
                proxyStoreId = response.id;
                console.log(
                    "Successfully stored data on proxy with ID:",
                    proxyStoreId
                );
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

    async function generateUserBKeys() {
        try {
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
            decryptionSteps = []; 
            
            if (!proxyStoreId) {
                errorMessage = "No proxy store ID available. Please store data first.";
                return;
            }

            if (!userBSecretKey) {
                decryptionSteps = [...decryptionSteps, "Generating User B keys..."];
                await delay(1000);
                const success = await generateUserBKeys();
                if (!success) return;
            }

            decryptionSteps = [...decryptionSteps, "Connecting to proxy server..."];
            await delay(800);
            decryptionSteps = [...decryptionSteps, "Requesting re-encrypted data from proxy..."];
            await delay(1500);
            const payload = await proxyClient.getStoredFile(proxyStoreId);
            if (!payload) {
                errorMessage = "Failed to retrieve data from proxy";
                return;
            }

            // download from google cloud storage
            const response = await fetch(payload.object_url, {
            });

            console.log("response", response);

            const encryptedData = await response.bytes();

            decryptionSteps = [...decryptionSteps, "Processing received data..."];
            await delay(1000);
            const firstLevelKey: pre.FirstLevelSymmetricKey = {
                first: pre.BN254CurveWrapper.pairing(secondLevelEncrypted!.encryptedKey.first, reEncryptionKey!),
                second: secondLevelEncrypted!.encryptedKey!.second
            };

            console.log("abc", arrayBufferToBase64(encryptedData).substring(0,10));

            decryptionSteps = [...decryptionSteps, "Decrypting data with User B's secret key..."];
            await delay(2000);
            const decryptedData = await client.preClient.decryptFirstLevel(
                {
                    encryptedKey: firstLevelKey,
                    encryptedMessage: new Uint8Array(encryptedData),
                    
                },
                userBSecretKey!
            );


            decryptionSteps = [...decryptionSteps, "Creating decrypted image..."];
            await delay(800);
            const blob = new Blob([decryptedData], { type: "image/jpeg" });
            decryptedImage = URL.createObjectURL(blob);

            decryptionSteps = [...decryptionSteps, "Decryption complete!"];
            decryptionDetails = "Successfully decrypted the image as user B";
            errorMessage = null;
        } catch (error: any) {
            console.error("Error decrypting data:", error);
            errorMessage = "Error decrypting data: " + error.message;
            decryptionDetails = null;
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

        return (
            parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i]
        );
    }

    function downloadEncryptedData() {
        if (secondLevelEncrypted && browser) {
            const blob = new Blob([secondLevelEncrypted.encryptedMessage], {
                type: "application/octet-stream",
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "encrypted-image.bin";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url); 
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

    function formatByteCount(bytes: number, decimals = 2) {
        if (bytes === 0) return "0 Bytes";

        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB", "TB"];

        const i = Math.min(
            Math.floor(Math.log(Math.abs(bytes)) / Math.log(k)),
            sizes.length - 1
        );

        return (
            parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) +
            " " +
            sizes[i]
        );
    }

    // Add these helper functions for encryption/decryption of shares
    async function encryptShare(
        share: Uint8Array,
        passphrase: string
    ): Promise<ArrayBuffer> {
        const encoder = new TextEncoder();
        const passphraseData = encoder.encode(passphrase);

        // Generate a key from the passphrase
        const key = await crypto.subtle.importKey(
            "raw",
            passphraseData,
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        // Generate encryption key
        const encryptionKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: new Uint8Array(16), // In production, use a random salt and store it
                iterations: 100000,
                hash: "SHA-256",
            },
            key,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
        );

        // Encrypt the share
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            encryptionKey,
            share
        );

        // Combine IV and encrypted data
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);

        return result.buffer;
    }

    async function decryptShare(
        encryptedData: ArrayBuffer,
        passphrase: string
    ): Promise<Uint8Array> {
        const encoder = new TextEncoder();
        const passphraseData = encoder.encode(passphrase);

        // Generate a key from the passphrase
        const key = await crypto.subtle.importKey(
            "raw",
            passphraseData,
            { name: "PBKDF2" },
            false,
            ["deriveBits", "deriveKey"]
        );

        // Generate decryption key
        const decryptionKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: new Uint8Array(16), // Use same salt as encryption
                iterations: 100000,
                hash: "SHA-256",
            },
            key,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        // Split IV and encrypted data
        const iv = new Uint8Array(encryptedData.slice(0, 12));
        const encryptedShare = new Uint8Array(encryptedData.slice(12));

        // Decrypt the share
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            decryptionKey,
            encryptedShare
        );

        return new Uint8Array(decrypted);
    }
</script>

<main class="container">
    <h1>Image Encryption App</h1>
    <div class="info-banner">
        <p>
            <strong>Privacy Notice:</strong> All processing happens in your browser.
            No data is sent to or stored on any server.
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

        {#if generatedSecretKeyDisplay}
            <div class="secret-key-display">
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
                    <span>{generatedSecretKeyDisplay}</span>
                </div>
            </div>
        {/if}

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
                        <li>Share {i + 1}: {arrayBufferToBase64(share)}</li>
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
                        <polyline points="3.27 6.96 12 12.01 20.73 6.96"
                        ></polyline>
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
                    <rect x="3" y="3" width="18" height="18" rx="2" ry="2"
                    ></rect>
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
                    Selected: {selectedFile.name} ({formatBytes(
                        selectedFile.size
                    )})
                </p>
            {/if}
        </div>

        {#if selectedFile}
            {#if storedShareInfo?.includes("with passphrase: Yes")}
                <div class="passphrase-container">
                    <label for="encrypt-passphrase"
                        >Enter encryption passphrase:</label
                    >
                    <input
                        id="encrypt-passphrase"
                        type="password"
                        class={passphraseError ? "input-error" : ""}
                        bind:value={encryptPassphrase}
                        placeholder="Enter the passphrase used during key generation"
                    />
                    <p class="passphrase-warning">
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
                                d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"
                            />
                            <line x1="12" y1="9" x2="12" y2="13" />
                            <line x1="12" y1="17" x2="12.01" y2="17" />
                        </svg>
                        This key requires a passphrase for encryption
                    </p>
                    {#if passphraseError}
                        <p class="passphrase-error">
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
                                <circle cx="12" cy="12" r="10" />
                                <line x1="15" y1="9" x2="9" y2="15" />
                                <line x1="9" y1="9" x2="15" y2="15" />
                            </svg>
                            {passphraseError}
                        </p>
                    {/if}
                </div>
            {/if}
            <button on:click={handleEncrypt}>Encrypt Image</button>

            {#if reconstructionSteps.length > 0}
                <div class="reconstruction-steps">
                    {#each reconstructionSteps as step, i}
                        <div class="status-item info {i === reconstructionSteps.length - 1 ? 'current' : 'completed'}">
                            <svg
                                xmlns="http://www.w3.org/2000/svg"
                                width="16"
                                height="16"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2"
                            >
                                {#if i === reconstructionSteps.length - 1}
                                    <!-- Loading spinner for current step -->
                                    <circle cx="12" cy="12" r="10" class="spinner" />
                                {:else}
                                    <!-- Checkmark for completed steps -->
                                    <path d="M12 2a10 10 0 0 1 10 10a10 10 0 0 1-10 10A10 10 0 0 1 2 12A10 10 0 0 1 12 2z" />
                                    <path d="M9 12l2 2l4-4" />
                                {/if}
                            </svg>
                            <span>{step}</span>
                        </div>
                    {/each}
                </div>
            {/if}

            {#if secretKeyDisplay}
                <div class="secret-key-display">
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
                        <span>{secretKeyDisplay}</span>
                    </div>
                </div>
            {/if}

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
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"
                            ></path>
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
                                    <h4>As Text</h4>
                                    <div class="encrypted-text">
                                        <p class="base64-preview">
                                            {encryptedBase64.substring(
                                                0,
                                                100
                                            )}...
                                        </p>
                                    </div>
                                </div>
                            </div>
                            <div class="data-info">
                                <p>Size: {formatByteCount(encryptedSize)}</p>
                                <button
                                    class="download-btn"
                                    on:click={downloadEncryptedData}
                                    disabled={!secondLevelEncrypted}
                                >
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
                                            d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"
                                        ></path>
                                        <polyline points="7 10 12 15 17 10"
                                        ></polyline>
                                        <line x1="12" y1="15" x2="12" y2="3"
                                        ></line>
                                    </svg>
                                    Download
                                </button>
                            </div>
                            <p class="note">
                                Note: These are two different ways to view the
                                same encrypted data
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
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"
                        ></path>
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
                {#if decryptionSteps.length > 0}
                    <div class="reconstruction-steps">
                        {#each decryptionSteps as step, i}
                            <div class="status-item info {i === decryptionSteps.length - 1 ? 'current' : 'completed'}">
                                <svg
                                    xmlns="http://www.w3.org/2000/svg"
                                    width="16"
                                    height="16"
                                    viewBox="0 0 24 24"
                                    fill="none"
                                    stroke="currentColor"
                                    stroke-width="2"
                                >
                                    {#if i === decryptionSteps.length - 1}
                                        <!-- Loading spinner for current step -->
                                        <circle cx="12" cy="12" r="10" class="spinner" />
                                    {:else}
                                        <!-- Checkmark for completed steps -->
                                        <path d="M12 2a10 10 0 0 1 10 10a10 10 0 0 1-10 10A10 10 0 0 1 2 12A10 10 0 0 1 12 2z" />
                                        <path d="M9 12l2 2l4-4" />
                                    {/if}
                                </svg>
                                <span>{step}</span>
                            </div>
                        {/each}
                    </div>
                {/if}

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

            <button on:click={handleDecryptAsB}>Start Decryption Process</button
            >

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
        width: 600px;
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

    .status-item.completed {
        background-color: #e8f5e9;
        color: #2e7d32;
        border: 1px solid #c8e6c9;
    }

    .status-item.completed svg {
        color: #2e7d32;
    }

    .status-item.current {
        background-color: #e3f2fd;
        color: #1976d2;
        border: 1px solid #bbdefb;
        border-left: 4px solid #1976d2;
    }

    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    .spinner {
        animation: spin 2s linear infinite;
        transform-origin: center;
    }

    .reconstruction-status {
        margin: 1rem 0;
    }

    .secret-key-display {
        margin: 1rem 0;
        font-family: monospace;
    }

    .passphrase-warning {
        display: flex;
        align-items: center;
        color: #f57c00;
        font-size: 0.9rem;
        margin-top: 0.5rem;
        background-color: #fff3e0;
        padding: 0.5rem;
        border-radius: 4px;
        border-left: 4px solid #f57c00;
    }

    .passphrase-warning svg {
        margin-right: 0.5rem;
        color: #f57c00;
    }

    .input-error {
        border-color: #dc3545 !important;
        background-color: #fff5f5;
    }

    .passphrase-error {
        display: flex;
        align-items: center;
        color: #dc3545;
        font-size: 0.9rem;
        margin-top: 0.5rem;
        background-color: #fff5f5;
        padding: 0.5rem;
        border-radius: 4px;
        border-left: 4px solid #dc3545;
    }

    .passphrase-error svg {
        margin-right: 0.5rem;
        color: #dc3545;
    }

    .reconstruction-steps {
        margin: 1rem 0;
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }

    .reconstruction-steps .status-item:last-child {
        background-color: #e8f5e9;
        color: #2e7d32;
        border: 1px solid #c8e6c9;
    }

    .reconstruction-steps .status-item:last-child svg {
        color: #2e7d32;
    }

    .download-btn:disabled {
        background-color: #ccc;
        cursor: not-allowed;
        opacity: 0.7;
    }

    .download-btn:disabled:hover {
        background-color: #ccc;
    }
</style>
