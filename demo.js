import { FogmaKEM } from './Fogma.js';

async function initDemo() {
    console.log("Generating Fogma parameters...");
    // Initialize key pair / public parameters (usually done once or loaded from storage)
    const fogma = await FogmaKEM.generate(1024);

    // Bob encapsulates a session key
    console.log("Bob encapsulating...");
    const { ciphertexts, sessionKey: bobKey } = await fogma.encapsulate();

    // Alice decapsulates
    console.log("Alice decapsulating...");
    const { sessionKey: aliceKey, isValid } = await fogma.decapsulate(ciphertexts);

    console.log("FO Valid:", isValid);
    console.log("Keys Match:", bobKey === aliceKey);
    console.log("Shared Session Key:", bobKey);
}

initDemo();
